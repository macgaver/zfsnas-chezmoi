package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
	"zfsnas/internal/termsessions"
	"zfsnas/system"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// muxVars is a tiny shim so handlers in this file don't import gorilla/mux
// repeatedly via mux.Vars().
func muxVars(r *http.Request, name string) string { return mux.Vars(r)[name] }

// aggregateEntry is one line in the cross-server terminal-sessions response.
// IsLocal is a UI convenience — true when the entry came from this server,
// false when it was fetched from a linked InterLink peer.
type aggregateEntry struct {
	termsessions.Snapshot
	ServerID       string `json:"server_id"`
	ServerHostname string `json:"server_hostname"`
	IsLocal        bool   `json:"is_local"`
}

// HandleListTerminalSessionsAggregate returns the union of this server's
// terminal sessions for the current user PLUS every linked InterLink
// peer's sessions for the same username. Used by the bottom terminal's
// rehydrate-on-open flow so closing the browser and coming back restores
// every shell the user had across every federated ZNAS at once.
//
// Per-peer call uses the same X-Interlink-Relay-* HMAC headers that
// RelayMiddleware uses for full-relay-mode forwarding (see relay.go) —
// the peer's RelayAuthMiddleware synthesises a session as the named user,
// so its /api/terminal-sessions returns that user's sessions on the peer.
//
// GET /api/terminal-sessions/aggregate
func HandleListTerminalSessionsAggregate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		username := sess.Username

		// Local sessions.
		out := make([]aggregateEntry, 0, 16)
		for _, s := range termsessions.Default.ListForUser(sess.UserID) {
			out = append(out, aggregateEntry{Snapshot: s, ServerID: "", ServerHostname: "", IsLocal: true})
		}

		// Linked peers — fan out in parallel, 3 s ceiling per peer so one
		// offline server doesn't stall the bottom-terminal open.
		type peerResult struct {
			id       string
			hostname string
			list     []termsessions.Snapshot
		}
		peers := append([]config.LinkedServer{}, appCfg.InterLink...)
		results := make(chan peerResult, len(peers))
		var wg sync.WaitGroup
		for _, lsCopy := range peers {
			ls := lsCopy
			wg.Add(1)
			go func() {
				defer wg.Done()
				snaps, err := fetchRemoteTerminalSessions(ls, username)
				if err != nil {
					return
				}
				results <- peerResult{id: ls.ID, hostname: ls.Hostname, list: snaps}
			}()
		}
		wg.Wait()
		close(results)
		for pr := range results {
			for _, s := range pr.list {
				out = append(out, aggregateEntry{Snapshot: s, ServerID: pr.id, ServerHostname: pr.hostname, IsLocal: false})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out) //nolint:errcheck
	}
}

// fetchRemoteTerminalSessions calls a peer's /api/terminal-sessions with
// relay HMAC headers identifying the current user. Returns whatever the
// peer's local list says (which excludes its own peers — no recursion).
func fetchRemoteTerminalSessions(ls config.LinkedServer, username string) ([]termsessions.Snapshot, error) {
	nonceBytes := make([]byte, 8)
	rand.Read(nonceBytes) //nolint:errcheck
	nonce := hex.EncodeToString(nonceBytes)
	ts := time.Now().Unix()
	sig := system.RelayForwardHMAC(ls.SharedSecret, username, ts, nonce)

	// Bound this quick "list sessions" call at 3s via the request CONTEXT — NOT
	// by setting client.Timeout, which would mutate the cached, shared relay
	// client and silently cap every other relay request (e.g. /api/updates/check
	// would then abort at 3s, surfacing as "the peer took too long to respond").
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(ls.URL, "/")+"/api/terminal-sessions", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Interlink-Relay-User", username)
	req.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Interlink-Relay-Nonce", nonce)
	req.Header.Set("X-Interlink-Relay-HMAC", sig)

	client := system.InterlinkClientForRelay(ls.TLSFingerprint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil //nolint:nilnil
	}
	var list []termsessions.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// HandleInterlinkTerminalProxyWS bridges a browser WebSocket to a linked
// peer's /ws/<kind-console> endpoint, using relay HMAC headers so the peer
// authenticates the connection as the current user. The bottom-terminal
// UI calls this for any tab tagged with a server_id (i.e. owned by a
// peer); local-only sessions use the existing /ws/<kind> path directly.
//
// GET /ws/interlink-terminal?server_id=<id>&kind=<k>&target=<t>[&session_id=<sid>][&cols=N&rows=M]
func HandleInterlinkTerminalProxyWS(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		q := r.URL.Query()
		serverID := q.Get("server_id")
		kind := q.Get("kind")
		target := q.Get("target")
		sessionID := q.Get("session_id")
		cols := q.Get("cols")
		rows := q.Get("rows")
		if serverID == "" || kind == "" {
			http.Error(w, "server_id and kind required", http.StatusBadRequest)
			return
		}

		// Find the peer.
		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == serverID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			http.Error(w, "linked server not found", http.StatusNotFound)
			return
		}

		// Build the peer-side WS path.
		var peerPath string
		switch kind {
		case termsessions.KindHost:
			peerPath = "/ws/terminal"
		case termsessions.KindUpdater:
			// Interactive OS update on the peer. target carries the peer hostname
			// (for the tab label only); the endpoint always upgrades its own host.
			peerPath = "/ws/updater"
		case termsessions.KindLXD:
			if target == "" {
				http.Error(w, "target required for lxd", http.StatusBadRequest)
				return
			}
			peerPath = "/ws/lxd-console?name=" + url.QueryEscape(target)
		case termsessions.KindCompose:
			stack, container, ok := splitTwo(target, ":")
			if !ok {
				http.Error(w, "target must be stack:container", http.StatusBadRequest)
				return
			}
			peerPath = "/ws/compose-console?stack=" + url.QueryEscape(stack) +
				"&container=" + url.QueryEscape(container)
		case termsessions.KindDocker:
			instance, container, ok := splitTwo(target, ":")
			if !ok {
				http.Error(w, "target must be instance:container", http.StatusBadRequest)
				return
			}
			peerPath = "/ws/docker-console?instance=" + url.QueryEscape(instance) +
				"&container=" + url.QueryEscape(container)
		default:
			http.Error(w, "unsupported kind", http.StatusBadRequest)
			return
		}
		sep := "&"
		if !strings.Contains(peerPath, "?") {
			sep = "?"
		}
		if sessionID != "" {
			peerPath += sep + "session_id=" + url.QueryEscape(sessionID)
			sep = "&"
		}
		if cols != "" && rows != "" {
			peerPath += sep + "cols=" + url.QueryEscape(cols) + "&rows=" + url.QueryEscape(rows)
			sep = "&"
		}
		// Forward the browser window id so the peer's multi-controller model can
		// tell windows apart, and the suffixed title for a 2nd+ session of the
		// same target (v6.6.11).
		if wid := q.Get("window_id"); wid != "" {
			peerPath += sep + "window_id=" + url.QueryEscape(wid)
			sep = "&"
		}
		if tt := q.Get("title"); tt != "" {
			peerPath += sep + "title=" + url.QueryEscape(tt)
		}

		// Upgrade browser side.
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		browserConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer browserConn.Close()

		// An open peer terminal counts as user activity — keep the local web
		// session alive or the inactivity evictor tears down this proxy's auth
		// (and every local PTY the user owns) after IdleTimeoutMinutes.
		stopKeepalive := wsSessionKeepalive(sess.Token)
		defer stopKeepalive()

		// Dial peer with relay HMAC headers as the current user.
		wsBase := ls.URL
		switch {
		case strings.HasPrefix(wsBase, "https://"):
			wsBase = "wss://" + wsBase[len("https://"):]
		case strings.HasPrefix(wsBase, "http://"):
			wsBase = "ws://" + wsBase[len("http://"):]
		}
		nonceBytes := make([]byte, 8)
		rand.Read(nonceBytes) //nolint:errcheck
		nonce := hex.EncodeToString(nonceBytes)
		ts := time.Now().Unix()
		sig := system.RelayForwardHMAC(ls.SharedSecret, sess.Username, ts, nonce)
		dialHeader := http.Header{}
		dialHeader.Set("X-Interlink-Relay-User", sess.Username)
		dialHeader.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
		dialHeader.Set("X-Interlink-Relay-Nonce", nonce)
		dialHeader.Set("X-Interlink-Relay-HMAC", sig)
		dialer := websocket.Dialer{TLSClientConfig: system.InterlinkTLSConfigForRelay(ls.TLSFingerprint)}
		remoteConn, dialResp, err := dialer.Dial(wsBase+peerPath, dialHeader)
		if err != nil {
			// A "bad handshake" means the peer answered with a non-101 status. The
			// common cause for a newer endpoint like /ws/updater is a peer running
			// an older ZNAS binary that doesn't have that route (404). Turn the
			// cryptic gorilla error into something actionable, and send it as a
			// fatal-error envelope so the client stops the reconnect loop.
			msg := "peer dial failed: " + err.Error()
			status := 0
			if dialResp != nil {
				status = dialResp.StatusCode
			}
			if status == http.StatusNotFound && kind == termsessions.KindUpdater {
				msg = "This server is running an older ZNAS version without the Interactive Update feature. Update its ZNAS binary first (Platform → Check for Releases), then try again."
			} else if status != 0 {
				msg += " (HTTP " + strconv.Itoa(status) + ")"
			}
			browserConn.WriteMessage(websocket.TextMessage,
				[]byte(`{"type":"error","error":"`+jsonEscape(msg)+`","fatal":true}`)) //nolint:errcheck
			return
		}
		defer remoteConn.Close()

		errc := make(chan struct{}, 2)
		go func() {
			for {
				mt, msg, err := remoteConn.ReadMessage()
				if err != nil {
					errc <- struct{}{}
					return
				}
				if err := browserConn.WriteMessage(mt, msg); err != nil {
					errc <- struct{}{}
					return
				}
			}
		}()
		go func() {
			for {
				mt, msg, err := browserConn.ReadMessage()
				if err != nil {
					errc <- struct{}{}
					return
				}
				if err := remoteConn.WriteMessage(mt, msg); err != nil {
					errc <- struct{}{}
					return
				}
			}
		}()
		<-errc
	}
}

// splitTwo returns the substrings on either side of the first occurrence
// of sep. ok=false if sep isn't present.
func splitTwo(s, sep string) (string, string, bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

// HandleCloseRemoteTerminalSession proxies a session-close to a linked
// peer using relay HMAC headers — so the X on a tab tagged with a peer's
// server_id actually terminates the PTY on the right server, not locally.
// POST /api/interlink/terminal-sessions/{server_id}/{id}/close
func HandleCloseRemoteTerminalSession(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		serverID := muxVars(r, "server_id")
		id := muxVars(r, "id")
		if serverID == "" || id == "" {
			jsonErr(w, http.StatusBadRequest, "server_id and id are required")
			return
		}
		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == serverID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		nonceBytes := make([]byte, 8)
		rand.Read(nonceBytes) //nolint:errcheck
		nonce := hex.EncodeToString(nonceBytes)
		ts := time.Now().Unix()
		sig := system.RelayForwardHMAC(ls.SharedSecret, sess.Username, ts, nonce)
		peerURL := strings.TrimRight(ls.URL, "/") + "/api/terminal-sessions/" + url.PathEscape(id) + "/close"
		// 5s deadline via context (NOT client.Timeout — that cached client is
		// shared by every relay request; mutating it caps them all).
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", peerURL, nil)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		req.Header.Set("X-Interlink-Relay-User", sess.Username)
		req.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Interlink-Relay-Nonce", nonce)
		req.Header.Set("X-Interlink-Relay-HMAC", sig)
		client := system.InterlinkClientForRelay(ls.TLSFingerprint)
		resp, err := client.Do(req)
		if err != nil {
			jsonErr(w, http.StatusBadGateway, "peer unreachable: "+err.Error())
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
	}
}

// Silence unused import linters when handler is built without certain
// kinds (defensive in case the io import becomes unused after edits).
var _ = io.Copy
