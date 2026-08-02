package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/system"

	"github.com/gorilla/websocket"
)

// relaySessionKey is the context key used by RelayAuthMiddleware to inject
// a synthetic session for requests arriving via a relay proxy.
const relaySessionKey contextKey = "relay_session"

// relayBypassPrefixes lists path prefixes that are always served locally on
// Server A and never forwarded to the remote when relay mode is active.
var relayBypassPrefixes = []string{
	"/api/auth/",
	"/api/interlink/",
	"/api/push-interlink/",
	"/api/prefs", // user preferences (theme etc.) always belong to home server
	"/ws/",
	"/static/",
	"/setup",
	"/login",
	"/interlink-login",
	"/apple-touch-icon",
}

// relayForwardInterlinkPaths are interlink/push-interlink HTTP paths that ARE
// forwarded to the remote server when relay mode is active, overriding the
// broad /api/interlink/ + /api/push-interlink/ bypass above. Rationale: when an
// operator is VIEWING peer B and pushes one of B's datasets, the whole push
// flow — the eligible-target server list, the remote pool/folder lookups, and
// the syncoid transfer itself — must run ON B (so it pushes B's dataset to one
// of B's own peers, which includes the home server A). Served locally on A, the
// target list was A's peers (excluding A, including B) — i.e. wrong, and missing
// the home server. The switcher's own /api/interlink/servers stays bypassed
// (local) so the server-switch dropdown keeps listing A's peers.
// relayForwardNonAPIPaths are non-/api/, non-/ws/ paths that MUST still be
// forwarded to the viewed peer. The catch-all at the end of isRelayBypassed
// keeps SPA routes and static assets local, which is right for everything the
// portal itself renders — but the service proxy is peer-scoped data served
// under a plain path, so it needs an explicit exemption. Without it, embedding
// any app belonging to a relayed peer answered "service not found", because the
// peer's service id was looked up in the LOCAL services.json.
var relayForwardNonAPIPaths = []string{
	"/s/", // v6.8.1 service reverse proxy
}

var relayForwardInterlinkPaths = []string{
	"/api/push-interlink/",           // start/start-dataset/servers/jobs/cancel/status
	"/api/interlink/remote-pools/",   // destination pool lookup on the viewed server
	"/api/interlink/remote-folders/", // destination folder lookup on the viewed server
}

// relayWSForwardPaths are WebSocket paths that ARE relayed to the remote server
// despite /ws/ being in the bypass list above.
var relayWSForwardPaths = []string{
	"/ws/terminal",
	"/ws/binary-update-apply",
	"/ws/updates-apply",
	"/ws/replication/",
	"/ws/lxd-console",
	"/ws/lxd-vga",
	// Live `zpool iostat` for the storage Topology hover bandwidth graphs must
	// run on the server being viewed — otherwise hovering a remote pool/dataset
	// opened the stream on the LOCAL portal (which has no such pool) and the
	// bandwidth/ops charts stayed empty.
	"/ws/zpool-iostat",
	"/ws/compose-logs",
	"/ws/compose-console",
	"/ws/docker-console",
	// Host-mutating install/migration streams must run on the server the
	// operator is actually viewing in relay mode — NOT the local portal.
	// Without these, e.g. enabling virtualization on a relayed peer ran the
	// netplan→ifupdown migration against the LOCAL box (already migrated →
	// "no /etc/netplan/*.yaml files found"), and prereq installs landed on
	// the wrong host. Same category as updates-apply / binary-update-apply.
	"/ws/prereqs-install",
	"/ws/memcomp-install",
	"/ws/lxd-migrate-netplan",
}

// relaySlowPrefixes are API path prefixes whose handlers run genuinely slow
// shell work on the peer (package indexing, dpkg/sudoers probing, a GitHub
// round-trip). Relayed requests to these get a long deadline so the proxy never
// aborts a healthy-but-slow response.
var relaySlowPrefixes = []string{
	"/api/updates/",       // apt-get update + simulate upgrade (the reported case)
	"/api/os-updates",     // package upgrade listing
	"/api/binary-update/", // GitHub release lookup
	"/api/prereqs",        // dpkg / package-presence probing
	"/api/sudoers/",       // sudo/visudo validation
}

// relayProxyTimeout returns the per-request deadline for a relayed path: a
// generous budget for the known-slow endpoints above, a snappy default for
// everything else.
func relayProxyTimeout(path string) time.Duration {
	for _, p := range relaySlowPrefixes {
		if strings.HasPrefix(path, p) {
			// Comfortably under the server's 300s WriteTimeout so the relay
			// returns a clean timeout error before the inbound connection is cut.
			return 4 * time.Minute
		}
	}
	return 60 * time.Second
}

// isRelayBypassed reports whether path should be served locally even when
// relay mode is active.
func isRelayBypassed(path string) bool {
	// WebSocket paths explicitly forwarded to the remote override the /ws/ bypass.
	for _, p := range relayWSForwardPaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	// Push-interlink flow paths forward to the viewed peer, overriding the broad
	// /api/interlink/ + /api/push-interlink/ bypass below.
	for _, p := range relayForwardInterlinkPaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	for _, prefix := range relayBypassPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	// Explicitly-forwarded non-API paths (the service proxy) must survive the
	// catch-all below.
	for _, p := range relayForwardNonAPIPaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	// Non-/api/ and non-/ws/ paths (SPA pages, root) are always served locally.
	if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/ws/") {
		return true
	}
	return false
}

// ── Server A: outbound relay proxy ──────────────────────────────────────────

// RelayMiddleware wraps the main router on Server A.  For sessions that are in
// relay mode it forwards API requests to the remote server with HMAC-signed
// identity headers and streams the remote response back to the browser.
// Paths in relayBypassPrefixes are always served locally.
func RelayMiddleware(appCfg *config.AppConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always serve local-only paths.
		if isRelayBypassed(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Per-request opt-out: the multi-terminal "+" menu is a fleet-wide view
		// and must reflect the TRUE local host + its peers even while the session
		// is relaying to a peer. Without this the relayed /api/version +
		// /api/lxd/instances resolve to the viewed peer (so it appears as "this
		// server"), while the locally-served fleet list still lists that same
		// peer — duplicating it and dropping the real local host (#2).
		//
		// The query-param form (znas_no_relay=1) is for WebSockets, where the
		// browser can't set a custom header: a local-host terminal tab opened
		// from the popout must connect to THIS portal's instance, not be
		// forwarded to the relayed peer (which would fail "Instance not found").
		if r.Header.Get("X-ZNAS-No-Relay") == "1" || r.URL.Query().Get("znas_no_relay") == "1" {
			next.ServeHTTP(w, r)
			return
		}

		// Read session token to look up relay state.
		cookie, err := r.Cookie("zfsnas_session")
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := session.Default.Get(cookie.Value)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		relay := session.GetRelay(cookie.Value)
		if relay == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Look up the linked server.
		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == relay.ServerID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			// Linked server no longer exists — exit relay mode, serve locally.
			session.ClearRelay(cookie.Value)
			next.ServeHTTP(w, r)
			return
		}

		// Build HMAC-signed relay identity headers.
		ts, nonceHex, sig := relayIdentityHeaders(ls, sess.Username)

		// WebSocket upgrade — bridge bidirectionally instead of HTTP proxy.
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			relayWebSocket(w, r, ls, sess.Username, ts, nonceHex, sig)
			return
		}

		// HTTP — proxy the request (URI forwarded verbatim) to the peer.
		proxyHTTPToPeer(w, r, ls, r.URL.RequestURI(), sess.Username, ts, nonceHex, sig)
	})
}

// relayIdentityHeaders mints the per-request HMAC identity (timestamp, nonce,
// signature) that Server B validates in RelayAuthMiddleware. Shared by the
// global RelayMiddleware and the per-peer HandleInterlinkRelay forwarder.
func relayIdentityHeaders(ls *config.LinkedServer, username string) (ts int64, nonceHex, sig string) {
	nonce := make([]byte, 8)
	rand.Read(nonce) //nolint:errcheck
	nonceHex = hex.EncodeToString(nonce)
	ts = time.Now().Unix()
	sig = system.RelayForwardHMAC(ls.SharedSecret, username, ts, nonceHex)
	return
}

// proxyHTTPToPeer forwards a single HTTP request to a linked peer at
// ls.URL+requestURI with the given relay identity headers, streaming the
// response back to the browser. Cookie/Origin are stripped on the way out and
// Set-Cookie on the way back so neither side's session crosses the boundary.
func proxyHTTPToPeer(w http.ResponseWriter, r *http.Request, ls *config.LinkedServer, requestURI, username string, ts int64, nonceHex, sig string) {
	targetURL := ls.URL + requestURI
	// Bound the proxied request with a per-endpoint deadline. Most endpoints
	// answer in well under a second, but a few wrap slow shell work on the peer
	// (apt-get update for /api/updates/*, dpkg/sudoers probing for prereqs, a
	// GitHub round-trip for binary-update) — those get a generous budget so the
	// relay doesn't abort them mid-flight. A genuinely unreachable peer still
	// fails fast via the relay client's dial/TLS-handshake timeouts, regardless
	// of this budget.
	ctx, cancel := context.WithTimeout(r.Context(), relayProxyTimeout(r.URL.Path))
	defer cancel()
	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL, r.Body)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "relay: failed to build proxy request")
		return
	}
	// Forward headers except Cookie (local session must never reach the remote) and
	// Origin (browser sends Origin: https://server-a which would fail EnforceOrigin
	// on Server B whose Host is server-b — strip it so Server B treats the request
	// as a trusted server-to-server call, which it is).
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Origin") {
			continue
		}
		for _, v := range vv {
			proxyReq.Header.Add(k, v)
		}
	}
	// Inject relay identity headers.
	proxyReq.Header.Set("X-Interlink-Relay-User", username)
	proxyReq.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	proxyReq.Header.Set("X-Interlink-Relay-Nonce", nonceHex)
	proxyReq.Header.Set("X-Interlink-Relay-HMAC", sig)

	// Execute via the TLS-pinned interlink transport.
	client := system.InterlinkClientForRelay(ls.TLSFingerprint)
	resp, err := client.Do(proxyReq)
	if err != nil {
		// Our per-request budget firing (a healthy-but-slow handler) reads as a
		// timeout, not the misleading "remote unreachable". A dial/TLS-handshake
		// failure (peer actually down) is NOT context.DeadlineExceeded, so it
		// still surfaces as "unreachable" below.
		if errors.Is(err, context.DeadlineExceeded) && r.Context().Err() == nil {
			jsonErr(w, http.StatusGatewayTimeout, "relay: the peer took too long to respond (timed out)")
			return
		}
		jsonErr(w, http.StatusBadGateway, "relay: remote unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// Copy response (skip Set-Cookie — remote must not set cookies on the browser).
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// relayWebSocket bridges a browser WebSocket connection to the remote server.
// Server A upgrades the browser connection, dials Server B with HMAC-signed
// headers, then forwards frames in both directions until either side closes.
func relayWebSocket(w http.ResponseWriter, r *http.Request, ls *config.LinkedServer, username string, ts int64, nonceHex, sig string) {
	// Capture requested subprotocols before upgrading so we can mirror them to Server B.
	requestedProtos := websocket.Subprotocols(r)

	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: requestedProtos,
	}
	browserConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer browserConn.Close()

	// Convert https:// → wss://, http:// → ws://.
	wsBase := ls.URL
	if strings.HasPrefix(wsBase, "https://") {
		wsBase = "wss://" + wsBase[len("https://"):]
	} else if strings.HasPrefix(wsBase, "http://") {
		wsBase = "ws://" + wsBase[len("http://"):]
	}
	wsURL := wsBase + r.URL.RequestURI()

	dialHeader := http.Header{}
	dialHeader.Set("X-Interlink-Relay-User", username)
	dialHeader.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	dialHeader.Set("X-Interlink-Relay-Nonce", nonceHex)
	dialHeader.Set("X-Interlink-Relay-HMAC", sig)
	// Subprotocols are forwarded via the Dialer.Subprotocols field below —
	// gorilla/websocket inserts the Sec-WebSocket-Protocol header itself.
	// Setting it explicitly here too triggers a "duplicate header not
	// allowed: Sec-Websocket-Protocol" error from gorilla, which broke
	// the VGA console relay specifically (SPICE is the only relayed WS
	// that requests a subprotocol — "binary" — so other relayed paths
	// like /ws/terminal and /ws/lxd-console were unaffected).

	dialer := websocket.Dialer{
		TLSClientConfig: system.InterlinkTLSConfigForRelay(ls.TLSFingerprint),
		Subprotocols:    requestedProtos,
	}
	remoteConn, _, err := dialer.Dial(wsURL, dialHeader)
	if err != nil {
		browserConn.WriteMessage(websocket.TextMessage, []byte("relay: could not connect to remote console: "+err.Error())) //nolint:errcheck
		return
	}
	defer remoteConn.Close()

	errc := make(chan error, 2)
	go func() {
		for {
			mt, msg, err := remoteConn.ReadMessage()
			if err != nil {
				errc <- err
				return
			}
			if err := browserConn.WriteMessage(mt, msg); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		for {
			mt, msg, err := browserConn.ReadMessage()
			if err != nil {
				errc <- err
				return
			}
			if err := remoteConn.WriteMessage(mt, msg); err != nil {
				errc <- err
				return
			}
		}
	}()
	<-errc
}

// ── Server B: inbound relay auth ─────────────────────────────────────────────

// RelayAuthMiddleware wraps the router on Server B.  When an inbound request
// carries relay identity headers it validates the HMAC against all known linked
// server secrets and injects a synthetic *session.Session into the context so
// that RequireAuth accepts the request without a browser cookie.
// Requests without relay headers pass through untouched (normal cookie auth).
func RelayAuthMiddleware(appCfg *config.AppConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("X-Interlink-Relay-User")
		if username == "" {
			next.ServeHTTP(w, r)
			return
		}

		tsStr := r.Header.Get("X-Interlink-Relay-TS")
		nonce := r.Header.Get("X-Interlink-Relay-Nonce")
		sig := r.Header.Get("X-Interlink-Relay-HMAC")

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			jsonErr(w, http.StatusUnauthorized, "relay: invalid timestamp")
			return
		}

		// Reject stale requests (±30 s — same window as all other interlink endpoints).
		age := time.Since(time.Unix(ts, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "relay: request timestamp out of range")
			return
		}

		// Validate HMAC against all known linked server shared secrets.
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.RelayForwardHMAC(ls.SharedSecret, username, ts, nonce)
			if hmac.Equal([]byte(expected), []byte(sig)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "relay: invalid HMAC")
			return
		}

		// Resolve the user from Server B's own user list (B's role applies).
		users, loadErr := config.LoadUsers()
		if loadErr != nil {
			jsonErr(w, http.StatusInternalServerError, "relay: failed to load users")
			return
		}
		user := config.FindUserByUsername(users, username)
		if user == nil || user.Role == config.RoleSMBOnly {
			jsonErr(w, http.StatusForbidden, "relay: user not authorised on this server")
			return
		}

		// Inject a synthetic session under relaySessionKey.  RequireAuth will
		// promote it to the regular sessionKey so all downstream handlers work
		// unchanged.
		syntheticSess := &session.Session{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
		}
		ctx := context.WithValue(r.Context(), relaySessionKey, syntheticSess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
