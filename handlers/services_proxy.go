package handlers

// Service reverse proxy (v6.8.1). Design + threat model:
// PLANS/plan-version-6.8.1.md §2 and §7. Read §2.1 and §2.8 before changing
// anything here.
//
// The proxy re-serves a guest application over the portal's own HTTPS origin so
// it can be framed at all: a direct iframe is blocked three ways (mixed content
// from our HTTPS origin to the app's HTTP, our own CSP, and the app's
// X-Frame-Options). Because re-serving means untrusted app JS is delivered from
// OUR origin, two things are mandatory and must never be relaxed together:
//
//  1. the frame is sandboxed WITHOUT allow-same-origin (opaque origin), and
//  2. every request here is session-authenticated — there is no anonymous path.
//
// Without (1) a hostile container image could call the portal API with the
// admin's cookie. Without (2) the portal becomes an open relay into the LAN.

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"zfsnas/internal/config"
)

// validateProxyTarget enforces spec §2.2. The proxy may only ever dial a
// private, unicast address:
//
//   - loopback is refused because it would let a crafted request reach the
//     portal's own admin API (or any other host-local daemon);
//   - link-local covers the cloud metadata endpoint (169.254.169.254);
//   - public addresses are refused because an instance address is always
//     private — allowing them would turn the portal into an open relay.
//
// This is the second line of defence. The caller separately requires the
// ip:port to already be present in services.json, so a target can never be
// taken from the request itself.
func validateProxyTarget(host string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d out of range", port)
	}
	if net.ParseIP(host) != nil {
		return validateProxyAddr(host)
	}
	// A hostname (custom services may be entered as an FQDN). Anything that
	// cannot be one is rejected without asking the resolver — a stray "host:port"
	// or a malformed IPv6 literal is a bug in the caller, not a lookup.
	if strings.ContainsAny(host, ":/ \t") || len(host) > 253 {
		return fmt.Errorf("unparseable target address %q", host)
	}
	// Every address it resolves to is checked, and at least one must be usable.
	// This is only the friendly, early error: the guarantee is enforced again at
	// dial time by guardedDialControl, which is what a name resolving
	// differently a second later (DNS rebinding) runs into.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve %q", host)
	}
	var lastErr error
	for _, ip := range ips {
		if lastErr = validateProxyAddr(ip.IP.String()); lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("%s resolves outside the private network (%v)", host, lastErr)
}

// validateProxyAddr applies the address policy to one concrete IP.
func validateProxyAddr(ip string) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("unparseable target address %q", ip)
	}
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("loopback target refused")
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return fmt.Errorf("link-local target refused")
	case addr.IsUnspecified(), addr.IsMulticast():
		return fmt.Errorf("non-unicast target refused")
	case !addr.IsPrivate():
		return fmt.Errorf("non-private target refused")
	}
	return nil
}

// guardedDialControl is the real SSRF boundary. net.Dialer calls it after DNS
// resolution with the CONCRETE address it is about to connect to, so a name
// that passed validation and then re-resolved to a public or host-local address
// is refused here. With several A records the dialer simply moves on to the
// next address, so a mixed private/public name still reaches its private one.
func guardedDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("unparseable dial address %q", address)
	}
	return validateProxyAddr(host)
}

// guardedDialer dials only addresses guardedDialControl accepts.
var guardedDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Control:   guardedDialControl,
}

// ServiceTarget is the resolved upstream for one service. Host is an IP for a
// discovered service and may be an FQDN for a custom one — it is used verbatim
// so the Host header, TLS SNI and certificate name all match what the user
// typed. Connecting safely is guardedDialer's job, not this struct's.
type ServiceTarget struct {
	Scheme string
	Host   string
	Port   int
	Path   string // optional base path the app lives under
}

// BaseURL is the upstream origin (no trailing slash), always with an explicit
// port — this is what the portal dials.
func (t ServiceTarget) BaseURL() string {
	return t.Scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// BrowserURL is the origin handed to the BROWSER for a tab or window. The
// scheme's default port is left off so the user sees the address they typed
// (https://pics.example.com, not https://pics.example.com:443).
func (t ServiceTarget) BrowserURL() string {
	if (t.Scheme == "https" && t.Port == 443) || (t.Scheme == "http" && t.Port == 80) {
		host := t.Host
		if strings.Contains(host, ":") { // IPv6 literal
			host = "[" + host + "]"
		}
		return t.Scheme + "://" + host
	}
	return t.BaseURL()
}

// resolveServiceTarget turns a stored entry into a dial target. Every field
// comes from the stored record — never from the request — which is what makes
// services.json the allowlist.
//
// This checks SHAPE only (scheme, host present, port in range). The private-
// address policy lives in resolveProxyTarget, because it applies to what the
// PORTAL dials, not to what the user's browser opens: a custom service on a
// public URL is perfectly valid to open in a tab, and refusing to store it
// meant an FQDN could not be added at all.
func resolveServiceTarget(e config.ServiceEntry) (ServiceTarget, error) {
	var t ServiceTarget

	if e.URLOverride != "" { // custom service
		u, err := url.Parse(e.URLOverride)
		if err != nil {
			return t, fmt.Errorf("invalid service URL: %w", err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return t, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
		host, portStr, splitErr := net.SplitHostPort(u.Host)
		port := 0
		if splitErr != nil {
			host = u.Host
			if u.Scheme == "https" {
				port = 443
			} else {
				port = 80
			}
		} else if port, err = strconv.Atoi(portStr); err != nil {
			return t, fmt.Errorf("invalid port in service URL")
		}
		if host == "" {
			return t, fmt.Errorf("service URL has no host")
		}
		t = ServiceTarget{Scheme: u.Scheme, Host: host, Port: port, Path: u.Path}
	} else {
		port := e.DetectedPort
		if e.PortOverride > 0 {
			port = e.PortOverride
		}
		scheme := e.SchemeOverride
		if scheme == "" {
			if port == 443 || port == 8443 {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		t = ServiceTarget{Scheme: scheme, Host: e.IP, Port: port, Path: e.PathOverride}
	}

	if t.Host == "" {
		return ServiceTarget{}, fmt.Errorf("no address known for this service")
	}
	if t.Port < 1 || t.Port > 65535 {
		return ServiceTarget{}, fmt.Errorf("port %d out of range", t.Port)
	}
	return t, nil
}

// resolveProxyTarget is resolveServiceTarget plus the address policy — the only
// form the PROXY may use, since it is the portal that does the dialing.
func resolveProxyTarget(e config.ServiceEntry) (ServiceTarget, error) {
	t, err := resolveServiceTarget(e)
	if err != nil {
		return ServiceTarget{}, err
	}
	if err := validateProxyTarget(t.Host, t.Port); err != nil {
		return ServiceTarget{}, err
	}
	return t, nil
}

// findService returns the stored entry for id.
func findService(id string) (config.ServiceEntry, bool) {
	list, err := config.LoadServices()
	if err != nil {
		return config.ServiceEntry{}, false
	}
	for _, e := range list {
		if e.ID == id {
			return e, true
		}
	}
	return config.ServiceEntry{}, false
}

// proxyHopHeaders are connection-scoped and must not be forwarded verbatim.
var proxyHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// The proxy never follows a redirect itself: an upstream Location could point
// off the allowlisted host, and following it server-side would be an SSRF. We
// hand the redirect back to the browser rewritten instead.
var noRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// serviceProxyClient verifies upstream certificates.
var serviceProxyClient = &http.Client{
	Timeout:       60 * time.Second,
	CheckRedirect: noRedirect,
	Transport:     &http.Transport{DialContext: guardedDialer.DialContext},
}

// serviceProxyClientInsecure skips upstream certificate verification.
//
// This is the DEFAULT for services, because self-hosted apps almost universally
// present self-signed certificates and would otherwise be unreachable. The
// exposure is bounded: the destination is already restricted to an allowlisted
// PRIVATE address (§2.2), the portal never forwards its own session cookie
// upstream, and this affects only the app connection — the browser-facing side
// still uses the portal's real certificate. Per-service, and overridable.
var serviceProxyClientInsecure = &http.Client{
	Timeout:       60 * time.Second,
	CheckRedirect: noRedirect,
	Transport: &http.Transport{
		DialContext:     guardedDialer.DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see comment
	},
}

func proxyClientFor(e config.ServiceEntry) *http.Client {
	if e.IgnoreTLSOn() {
		return serviceProxyClientInsecure
	}
	return serviceProxyClient
}

// proxyErr answers a failed proxy request. Sub-resource requests get the usual
// JSON; a document request (the panel's own frame, or a tab) gets a small HTML
// page, because JSON painted into the frame is what the user would otherwise
// read. No app content is involved, so the portal's own styling is safe here.
func proxyErr(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		jsonErr(w, status, title+": "+detail)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8">
<style>body{margin:0;display:flex;align-items:center;justify-content:center;height:100vh;
background:#16181d;color:#c9d1d9;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
div{max-width:460px;padding:24px;text-align:center}h1{font-size:15px;margin:0 0 10px;color:#f0f6fc}
p{margin:0;font-size:12.5px;color:#8b949e}</style>
<div><h1>%s</h1><p>%s</p></div>`, html.EscapeString(title), html.EscapeString(detail))
}

// HandleServiceProxy serves /s/{id}/* — see the file header for the security
// contract. This handler assumes RequireAuth + RequirePermission have already
// run; it must never be registered without them.
func HandleServiceProxy(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !appCfg.ServiceProxyOn() {
			jsonErr(w, http.StatusForbidden, "service proxy is disabled")
			return
		}
		id := mux.Vars(r)["id"]
		entry, ok := findService(id)
		if !ok {
			jsonErr(w, http.StatusNotFound, "service not found")
			return
		}
		target, err := resolveProxyTarget(entry)
		if err != nil {
			// The frame loads this response, so a JSON body would render as raw
			// text inside the panel. Say it in prose when a document is what was
			// asked for. Reachable in normal use since a custom service may name
			// any host: the browser can open it in a tab, but the PORTAL only
			// dials private addresses.
			proxyErr(w, r, http.StatusBadGateway, "This service cannot be displayed inside the portal",
				"The portal fetches embedded apps itself, and it only connects to addresses on your "+
					"private network — "+err.Error()+". Open it in a new tab instead: your browser "+
					"reaches it directly.")
			return
		}

		prefix := "/s/" + id
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		if rest == "" {
			rest = "/"
		}
		// Map onto the upstream HOST ROOT, not the service's base path. Apps
		// routinely redirect outside their own subpath (an auth portal on
		// /cmlogin, say); scoping the proxy to the subpath made those escape
		// the proxy and get blocked as mixed content. The configured path is
		// the entry point only — see decorateService, which points the iframe
		// at /s/{id}<path>/.
		upstreamPath := rest

		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			proxyServiceWebSocket(w, r, target, upstreamPath, entry.IgnoreTLSOn())
			return
		}
		proxyServiceHTTP(w, r, target, upstreamPath, prefix, proxyClientFor(entry))
	}
}

func proxyServiceHTTP(w http.ResponseWriter, r *http.Request, t ServiceTarget, upstreamPath, prefix string, client *http.Client) {
	u := t.BaseURL() + upstreamPath
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, r.Body)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "bad upstream request")
		return
	}
	for k, vv := range r.Header {
		if isHopHeader(k) {
			continue
		}
		if strings.EqualFold(k, "Cookie") {
			// The app's OWN cookies must reach it — a token-based login (any
			// PHP app, OPNsense included) validates its CSRF token against the
			// session the cookie names, so dropping the header made every such
			// login fail with "CSRF check failed". The portal's own cookies are
			// filtered out by name, which is what spec §2.3 actually requires.
			if c := appCookiesUpstream(strings.Join(vv, "; ")); c != "" {
				req.Header.Set("Cookie", c)
			}
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Accept-Encoding", "identity") // keep bodies rewritable

	resp, err := client.Do(req)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, "service unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		switch {
		case isHopHeader(k):
			continue
		case strings.EqualFold(k, "X-Frame-Options"):
			continue // stripped so the app can be framed (spec §2.3)
		case strings.EqualFold(k, "Content-Security-Policy"),
			strings.EqualFold(k, "Content-Security-Policy-Report-Only"):
			for _, v := range vv {
				if s := stripFrameAncestors(v); s != "" {
					w.Header().Add(k, s)
				}
			}
			continue
		case strings.EqualFold(k, "Set-Cookie"):
			for _, v := range vv {
				w.Header().Add(k, rewriteSetCookie(v, prefix))
			}
			continue
		case strings.EqualFold(k, "Location"):
			for _, v := range vv {
				w.Header().Add(k, rewriteLocation(v, t, prefix))
			}
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// Rewrite HTML so an app served under /s/{id}/ resolves its RELATIVE assets
	// against the proxy prefix rather than the portal root. Absolute paths
	// (src="/static/…") still cannot be fixed this way — those apps fall back to
	// a new window (spec §7.1).
	if isHTMLResponse(resp.Header.Get("Content-Type")) {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxRewriteBytes))
		if err == nil {
			body = injectBaseHref(body, prefix+"/")
			body = rewriteAbsolutePaths(body, prefix)
			w.Header().Del("Content-Length")
			w.WriteHeader(resp.StatusCode)
			w.Write(body) //nolint:errcheck
			return
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// maxRewriteBytes bounds the HTML we will buffer in order to rewrite it.
// Anything larger is streamed through untouched rather than held in memory.
const maxRewriteBytes = 4 << 20

func isHTMLResponse(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/html")
}

var headOpenRe = regexp.MustCompile(`(?i)<head[^>]*>`)

// injectBaseHref inserts <base href="…"> as the first child of <head> so the
// app's relative URLs resolve under the proxy prefix. An existing <base> is left
// alone — the app knows its own layout better than we do.
func injectBaseHref(body []byte, base string) []byte {
	if regexp.MustCompile(`(?i)<base\s`).Match(body) {
		return body
	}
	loc := headOpenRe.FindIndex(body)
	if loc == nil {
		return body
	}
	tag := []byte(`<base href="` + base + `">`)
	out := make([]byte, 0, len(body)+len(tag))
	out = append(out, body[:loc[1]]...)
	out = append(out, tag...)
	out = append(out, body[loc[1]:]...)
	return out
}

func proxyServiceWebSocket(w http.ResponseWriter, r *http.Request, t ServiceTarget, upstreamPath string, ignoreTLS bool) {
	protos := websocket.Subprotocols(r)
	up := websocket.Upgrader{
		// Same-origin only: the frame is served from our origin, so a genuine
		// app WS comes back to us with our Origin. Anything else is refused.
		CheckOrigin: func(req *http.Request) bool {
			o := req.Header.Get("Origin")
			return o == "" || o == "null" || strings.HasSuffix(o, "://"+req.Host)
		},
		Subprotocols: protos,
	}
	browserConn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer browserConn.Close()

	scheme := "ws"
	if t.Scheme == "https" {
		scheme = "wss"
	}
	wsURL := scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) + upstreamPath
	if r.URL.RawQuery != "" {
		wsURL += "?" + r.URL.RawQuery
	}

	hdr := http.Header{}
	for k, vv := range r.Header {
		lk := strings.ToLower(k)
		if isHopHeader(k) || strings.HasPrefix(lk, "sec-websocket") || lk == "origin" {
			continue
		}
		if lk == "cookie" {
			// Same rule as the HTTP path: the app's session cookie is usually
			// what authorizes its websocket, the portal's never leaves.
			if c := appCookiesUpstream(strings.Join(vv, "; ")); c != "" {
				hdr.Set("Cookie", c)
			}
			continue
		}
		for _, v := range vv {
			hdr.Add(k, v)
		}
	}

	dialer := websocket.Dialer{
		Subprotocols:     protos,
		HandshakeTimeout: 15 * time.Second,
		NetDialContext:   guardedDialer.DialContext, // same address policy as HTTP
	}
	if ignoreTLS {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // same rationale as the HTTP client
	}
	upstream, _, err := dialer.Dial(wsURL, hdr)
	if err != nil {
		return
	}
	defer upstream.Close()

	errc := make(chan error, 2)
	go func() {
		for {
			mt, msg, err := upstream.ReadMessage()
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
			if err := upstream.WriteMessage(mt, msg); err != nil {
				errc <- err
				return
			}
		}
	}()
	<-errc
}

func isHopHeader(k string) bool {
	for _, h := range proxyHopHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return false
}

// stripFrameAncestors removes a frame-ancestors directive from an upstream CSP
// so the app's own policy can't veto being framed by the portal. Everything
// else in the app's policy is preserved.
func stripFrameAncestors(csp string) string {
	parts := strings.Split(csp, ";")
	kept := parts[:0]
	for _, p := range parts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "frame-ancestors") {
			continue
		}
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ";")
}

// portalCookiePrefix covers every cookie the PORTAL itself sets (currently just
// zfsnas_session, middleware.go). Matching on the prefix rather than the exact
// name means a future portal cookie is filtered from day one instead of
// silently leaking into every guest app.
const portalCookiePrefix = "zfsnas_"

// hostPrefixMangle stands in for the `__Host-` cookie name prefix while a
// cookie lives on the portal origin. Browsers only accept a `__Host-` cookie
// when it has Path=/ and no Domain — and scoping an app's cookies to its own
// /s/{id}/ prefix requires changing exactly those — so keeping the name verbatim
// would make the browser discard the cookie outright. It is renamed on the way
// down and restored on the way up, so the app only ever sees its own name. The
// prefix deliberately does NOT start with zfsnas_, or the filter above would
// eat it.
const hostPrefixMangle = "znasx-host-"

// rewriteSetCookie makes an app's cookie usable on the portal origin:
//
//   - Path is scoped to the service's proxy prefix, so one app's cookies are
//     never broadcast to another's (or to the portal).
//   - Domain is dropped. It names the app's own host, which the browser would
//     reject against our origin — the cookie would vanish silently.
//   - SameSite=None; Secure, because the panel frame is sandboxed without
//     allow-same-origin. Such a document has a null "site for cookies" in some
//     engines, which withholds Lax/Strict cookies from the very requests the
//     app makes to log itself in. None is safe here: reaching /s/{id}/ at all
//     still requires zfsnas_session, which stays SameSite=Lax and is what
//     withholds a cross-site POST (middleware.go, spec §2.8). Secure is
//     mandatory alongside None and always true — the portal is HTTPS-only.
func rewriteSetCookie(sc, prefix string) string {
	if strings.TrimSpace(sc) == "" {
		return sc
	}
	parts := strings.Split(sc, ";")
	nameVal := strings.TrimSpace(parts[0])
	if strings.HasPrefix(nameVal, "__Host-") {
		nameVal = hostPrefixMangle + strings.TrimPrefix(nameVal, "__Host-")
	}

	out := make([]string, 0, len(parts)+3)
	out = append(out, nameVal)
	var hasPath, hasSameSite, hasSecure bool
	for _, p := range parts[1:] {
		attr := strings.TrimSpace(p)
		switch la := strings.ToLower(attr); {
		case la == "":
			continue
		case strings.HasPrefix(la, "path="):
			out = append(out, "Path="+prefix+"/")
			hasPath = true
		case strings.HasPrefix(la, "domain="):
			continue // host-only on the portal origin
		case strings.HasPrefix(la, "samesite="):
			out = append(out, "SameSite=None")
			hasSameSite = true
		case la == "secure":
			out = append(out, attr)
			hasSecure = true
		default:
			out = append(out, attr)
		}
	}
	if !hasPath {
		out = append(out, "Path="+prefix+"/")
	}
	if !hasSameSite {
		out = append(out, "SameSite=None")
	}
	if !hasSecure {
		out = append(out, "Secure")
	}
	return strings.Join(out, "; ")
}

// appCookiesUpstream returns the Cookie header to send to the app: everything
// the browser offered MINUS the portal's own cookies, with any mangled
// `__Host-` name restored. Path scoping (rewriteSetCookie) already keeps one
// service's cookies away from another, so what arrives here is this app's own
// jar plus the portal's — and the portal's is precisely what must not leave.
func appCookiesUpstream(raw string) string {
	out := make([]string, 0, 8)
	for _, c := range strings.Split(raw, ";") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		name := c
		if i := strings.IndexByte(c, '='); i >= 0 {
			name = strings.TrimSpace(c[:i])
		}
		if strings.HasPrefix(strings.ToLower(name), portalCookiePrefix) {
			continue
		}
		if strings.HasPrefix(name, hostPrefixMangle) {
			c = "__Host-" + c[len(hostPrefixMangle):]
		}
		out = append(out, c)
	}
	return strings.Join(out, "; ")
}

// rewriteLocation keeps redirects inside the proxy. An absolute URL pointing at
// the same upstream is rewritten to its proxied form; one pointing anywhere
// else is passed through untouched so the BROWSER decides (we never fetch it).
func rewriteLocation(loc string, t ServiceTarget, prefix string) string {
	if strings.HasPrefix(loc, "/") {
		return prefix + loc
	}
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	// Compare HOSTNAMES only: the same app often redirects between :443 and
	// :80, or https → http, and all of those are still upstream.
	if u.Hostname() == t.Host {
		p := u.Path
		if p == "" {
			p = "/"
		}
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		return prefix + p
	}
	return loc
}



// absAttrRe matches src="/…" / href="/…" attributes holding a same-origin
// ABSOLUTE path. The negative lookahead-free construction excludes "//" (which
// is protocol-relative and belongs to another host) by requiring the character
// after the slash to be something other than a slash.
var absAttrRe = regexp.MustCompile(`(?i)\b(src|href)="(/[^/"][^"]*|/)"`)

// rewriteAbsolutePaths prefixes same-origin absolute asset paths with the
// service's proxy prefix.
//
// <base href> only affects RELATIVE URLs, so an app that writes
// src="/_app/entry.js" (SvelteKit/Immich, among many) still resolves against the
// origin root, misses the /s/{id} prefix and 404s — the app then renders blank.
// External (https://…, //host/…) and relative references are left untouched, as
// are paths already under the prefix.
func rewriteAbsolutePaths(body []byte, prefix string) []byte {
	p := []byte(prefix)
	return absAttrRe.ReplaceAllFunc(body, func(m []byte) []byte {
		sub := absAttrRe.FindSubmatch(m)
		if len(sub) != 3 {
			return m
		}
		path := sub[2]
		if bytes.HasPrefix(path, append(append([]byte{}, p...), '/')) || bytes.Equal(path, p) {
			return m // already proxied
		}
		out := make([]byte, 0, len(m)+len(p))
		out = append(out, sub[1]...)
		out = append(out, '=', '"')
		out = append(out, p...)
		out = append(out, path...)
		out = append(out, '"')
		return out
	})
}
