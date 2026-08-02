package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"zfsnas/internal/config"
)

// validateProxyTarget is a security control (spec §2.2). These tests exist so a
// future refactor cannot quietly widen what the proxy is willing to dial.
func TestValidateProxyTargetRejectsDangerousHosts(t *testing.T) {
	bad := []struct{ ip, why string }{
		{"127.0.0.1", "loopback would let a crafted request reach the portal's own admin API"},
		{"127.0.0.53", "loopback range, not just .1"},
		{"::1", "IPv6 loopback"},
		{"169.254.169.254", "cloud metadata endpoint"},
		{"169.254.1.1", "link-local"},
		{"8.8.8.8", "public internet — never an instance address"},
		{"0.0.0.0", "unspecified"},
		{"224.0.0.1", "multicast"},
		{"", "empty"},
		{"not-an-ip", "unparseable"},
		{"10.0.0.5:8080", "host:port passed where an IP is expected"},
	}
	for _, c := range bad {
		if err := validateProxyTarget(c.ip, 8080); err == nil {
			t.Errorf("validateProxyTarget(%q) allowed — %s", c.ip, c.why)
		}
	}
}

func TestValidateProxyTargetAllowsPrivate(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "192.168.2.50", "172.16.4.9", "fd00::1"} {
		if err := validateProxyTarget(ip, 8096); err != nil {
			t.Errorf("validateProxyTarget(%q) rejected: %v", ip, err)
		}
	}
}

func TestValidateProxyTargetPortRange(t *testing.T) {
	for _, p := range []int{0, -1, 65536, 99999} {
		if err := validateProxyTarget("10.0.0.5", p); err == nil {
			t.Errorf("port %d allowed", p)
		}
	}
	if err := validateProxyTarget("10.0.0.5", 65535); err != nil {
		t.Errorf("port 65535 should be valid: %v", err)
	}
}

// ── Spec §2.8: the proxy is never open ──────────────────────────────────────

// An unauthenticated request must be refused, for the entry document, for any
// sub-resource, and for an id that does not exist — with the SAME status, so
// the endpoint cannot be used to enumerate which services this host runs.
func TestServiceProxyRequiresSession(t *testing.T) {
	h := RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached without a session — the proxy would be an open relay")
	}))
	for _, path := range []string{
		"/s/abc/",
		"/s/abc/static/app.js",
		"/s/abc/api/login",
		"/s/doesnotexist/",
	} {
		req := httptest.NewRequest("GET", path, nil) // no session cookie
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d", path, rec.Code)
		}
	}
}

// A homepage API key must NOT unlock the proxy. Those keys are scoped to the
// read-only TrueNAS endpoints; honouring them here would turn a leaked
// dashboard key into a proxy into the private network.
func TestServiceProxyRejectsAPIKey(t *testing.T) {
	h := RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API key unlocked the service proxy")
	}))
	req := httptest.NewRequest("GET", "/s/abc/", nil)
	req.Header.Set("Authorization", "Bearer some-homepage-api-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for API-key auth on the proxy, got %d", rec.Code)
	}
}

// A WebSocket upgrade is just another request: it must be authenticated too,
// or a hostile page could stream from an internal app anonymously.
func TestServiceProxyWebSocketRequiresSession(t *testing.T) {
	h := RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unauthenticated WebSocket upgrade reached the proxy")
	}))
	req := httptest.NewRequest("GET", "/s/abc/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for an unauthenticated WS upgrade, got %d", rec.Code)
	}
}

// The proxy must refuse to serve when the kill switch is off (spec §2.6).
func TestServiceProxyDisabledReturns403(t *testing.T) {
	off := false
	cfg := &config.AppConfig{ServiceProxyEnabled: &off}
	req := httptest.NewRequest("GET", "/s/abc/", nil)
	rec := httptest.NewRecorder()
	HandleServiceProxy(cfg)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when the proxy is disabled, got %d", rec.Code)
	}
}

// Disabling discovery must disable the proxy too — it is the master switch.
func TestServiceProxyDisabledByDiscoveryKillSwitch(t *testing.T) {
	off := false
	cfg := &config.AppConfig{ServiceDiscoveryEnabled: &off}
	req := httptest.NewRequest("GET", "/s/abc/", nil)
	rec := httptest.NewRecorder()
	HandleServiceProxy(cfg)(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403 when discovery is off, got %d", rec.Code)
	}
}

// resolveProxyTarget is the security boundary: a hand-edited services.json must
// not turn the PROXY into an SSRF primitive. (resolveServiceTarget itself is
// shape-only — what the browser opens in a tab is not what the portal dials.)
func TestResolveProxyTargetRejectsDangerousEntries(t *testing.T) {
	for _, e := range []config.ServiceEntry{
		{IP: "127.0.0.1", DetectedPort: 8080},
		{IP: "169.254.169.254", DetectedPort: 80},
		{IP: "8.8.8.8", DetectedPort: 80},
		{URLOverride: "http://127.0.0.1:8443"},
		{URLOverride: "file:///etc/passwd"},
		{URLOverride: "http://169.254.169.254/latest/meta-data"},
		{IP: "10.0.0.5", DetectedPort: 0}, // nothing published
	} {
		if _, err := resolveProxyTarget(e); err == nil {
			t.Errorf("resolveProxyTarget allowed a dangerous entry: %+v", e)
		}
	}
}

// A custom service may be entered as an FQDN. Storing it must work — it is a
// perfectly good "open in a tab" target — with the host kept verbatim so the
// Host header, SNI and certificate name all line up if it is also proxied.
func TestResolveServiceTargetAcceptsFQDN(t *testing.T) {
	tgt, err := resolveServiceTarget(config.ServiceEntry{URLOverride: "https://pics.chezmoi.ca/albums"})
	if err != nil {
		t.Fatalf("FQDN service rejected: %v", err)
	}
	if tgt.Host != "pics.chezmoi.ca" || tgt.Port != 443 || tgt.Scheme != "https" {
		t.Errorf("got %+v", tgt)
	}
	if tgt.BaseURL() != "https://pics.chezmoi.ca:443" {
		t.Errorf("base URL: %q", tgt.BaseURL())
	}
	if tgt.Path != "/albums" {
		t.Errorf("path lost: %q", tgt.Path)
	}
	// An explicit port survives, and http defaults to 80.
	tgt, _ = resolveServiceTarget(config.ServiceEntry{URLOverride: "http://nas.lan:8080"})
	if tgt.Host != "nas.lan" || tgt.Port != 8080 {
		t.Errorf("got %+v", tgt)
	}
	tgt, _ = resolveServiceTarget(config.ServiceEntry{URLOverride: "http://nas.lan"})
	if tgt.Port != 80 {
		t.Errorf("http default port: %d", tgt.Port)
	}
	// Still shape-checked: no host, bad scheme.
	if _, err := resolveServiceTarget(config.ServiceEntry{URLOverride: "https://"}); err == nil {
		t.Error("hostless URL accepted")
	}
}

// The dial-time guard is what a DNS answer that changes between validation and
// connection runs into — it sees the concrete address, so no name can smuggle a
// public or host-local target past it.
func TestGuardedDialControlEnforcesAddressPolicy(t *testing.T) {
	for _, addr := range []string{"8.8.8.8:443", "127.0.0.1:8443", "169.254.169.254:80", "[::1]:443"} {
		if err := guardedDialControl("tcp", addr, nil); err == nil {
			t.Errorf("dial to %s allowed", addr)
		}
	}
	for _, addr := range []string{"10.0.0.5:8096", "192.168.2.50:443", "[fd00::1]:80"} {
		if err := guardedDialControl("tcp", addr, nil); err != nil {
			t.Errorf("dial to %s refused: %v", addr, err)
		}
	}
}

func TestResolveServiceTargetAcceptsValid(t *testing.T) {
	tgt, err := resolveServiceTarget(config.ServiceEntry{IP: "10.0.0.5", DetectedPort: 8096})
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if tgt.BaseURL() != "http://10.0.0.5:8096" {
		t.Errorf("got %q", tgt.BaseURL())
	}
	// 8443 implies https.
	tgt, err = resolveServiceTarget(config.ServiceEntry{IP: "10.0.0.5", DetectedPort: 8443})
	if err != nil || tgt.Scheme != "https" {
		t.Errorf("want https for 8443, got %q (%v)", tgt.Scheme, err)
	}
	// An override wins over the detected port.
	tgt, _ = resolveServiceTarget(config.ServiceEntry{IP: "10.0.0.5", DetectedPort: 8096, PortOverride: 9000})
	if tgt.Port != 9000 {
		t.Errorf("port override ignored: %d", tgt.Port)
	}
}

// Response hygiene (spec §2.3).
func TestStripFrameAncestors(t *testing.T) {
	got := stripFrameAncestors("default-src 'self'; frame-ancestors 'none'; img-src *")
	if strings.Contains(strings.ToLower(got), "frame-ancestors") {
		t.Errorf("frame-ancestors survived: %q", got)
	}
	if !strings.Contains(got, "default-src") || !strings.Contains(got, "img-src") {
		t.Errorf("other directives lost: %q", got)
	}
}

func TestRewriteSetCookieScopesToService(t *testing.T) {
	got := rewriteSetCookie("sid=abc; Path=/; HttpOnly", "/s/xyz")
	if !strings.Contains(got, "Path=/s/xyz/") {
		t.Errorf("cookie not scoped to the service: %q", got)
	}
	if !strings.Contains(got, "HttpOnly") {
		t.Errorf("unrelated attribute dropped: %q", got)
	}
	// A cookie with no Path must still be scoped, not left global.
	got = rewriteSetCookie("sid=abc; HttpOnly", "/s/xyz")
	if !strings.Contains(got, "Path=/s/xyz/") {
		t.Errorf("pathless cookie not scoped: %q", got)
	}
}

// The panel frame is sandboxed (opaque origin), so a Lax/Strict cookie can be
// withheld from the app's own login POST. Every proxied cookie is therefore
// re-attributed None+Secure, and the app's Domain — which names a host that is
// not ours — must go, or the browser drops the cookie on the floor.
func TestRewriteSetCookieMakesCookieUsableInSandboxedFrame(t *testing.T) {
	got := rewriteSetCookie("PHPSESSID=abc; path=/; domain=opnsense.lan; SameSite=Lax", "/s/xyz")
	if !strings.Contains(got, "SameSite=None") || strings.Contains(got, "SameSite=Lax") {
		t.Errorf("SameSite not relaxed: %q", got)
	}
	if !strings.Contains(got, "Secure") {
		t.Errorf("SameSite=None without Secure is rejected by browsers: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "domain=") {
		t.Errorf("upstream Domain survived: %q", got)
	}
	// Secure must not be duplicated when the app already set it.
	got = rewriteSetCookie("sid=abc; Secure; HttpOnly", "/s/xyz")
	if strings.Count(got, "Secure") != 1 {
		t.Errorf("Secure duplicated: %q", got)
	}
}

// A __Host- cookie cannot keep its name once we re-scope its Path, so it is
// renamed on the way down and MUST come back on the way up — otherwise the app
// receives a cookie it does not recognise.
func TestHostPrefixedCookieRoundTrips(t *testing.T) {
	down := rewriteSetCookie("__Host-nc_session=abc; Path=/; Secure", "/s/xyz")
	if strings.Contains(down, "__Host-") {
		t.Errorf("__Host- name kept despite a scoped Path — browser would drop it: %q", down)
	}
	name := strings.SplitN(down, ";", 2)[0]
	if up := appCookiesUpstream(name); up != "__Host-nc_session=abc" {
		t.Errorf("__Host- name not restored upstream: got %q", up)
	}
}

// The whole point of the header filter: the app gets its own session back, and
// never the portal's.
func TestAppCookiesUpstreamStripsPortalSession(t *testing.T) {
	got := appCookiesUpstream("zfsnas_session=SECRET; PHPSESSID=abc; theme=dark")
	if strings.Contains(got, "SECRET") || strings.Contains(got, "zfsnas_session") {
		t.Fatalf("portal session leaked upstream: %q", got)
	}
	if !strings.Contains(got, "PHPSESSID=abc") || !strings.Contains(got, "theme=dark") {
		t.Errorf("app cookies lost — its login can never validate: %q", got)
	}
	// Any future portal cookie is covered by the prefix, not just the session.
	if got := appCookiesUpstream("zfsnas_prefs=x; sid=1"); got != "sid=1" {
		t.Errorf("portal-prefixed cookie leaked: %q", got)
	}
	// Nothing to forward must yield an empty header, not "; ".
	if got := appCookiesUpstream("zfsnas_session=SECRET"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestRewriteLocationKeepsRedirectsInsideProxy(t *testing.T) {
	tgt := ServiceTarget{Scheme: "http", Host: "10.0.0.5", Port: 8096}
	if got := rewriteLocation("/login", tgt, "/s/xyz"); got != "/s/xyz/login" {
		t.Errorf("relative redirect: got %q", got)
	}
	if got := rewriteLocation("http://10.0.0.5:8096/login", tgt, "/s/xyz"); got != "/s/xyz/login" {
		t.Errorf("absolute same-host redirect: got %q", got)
	}
	// Off-host redirects are handed to the browser untouched — we never follow
	// them server-side (that would be an SSRF).
	if got := rewriteLocation("https://accounts.example.com/oauth", tgt, "/s/xyz"); got != "https://accounts.example.com/oauth" {
		t.Errorf("off-host redirect rewritten: got %q", got)
	}
}

// An app that references its assets with ABSOLUTE paths cannot be fixed by
// <base href> — the browser resolves "/x.js" against the origin root, missing
// the /s/{id} prefix, so every bundle 404s and the app renders blank. Immich
// (SvelteKit) does exactly this. Rewriting the attributes fixes the initial
// load; URLs the app builds at runtime in JS remain out of reach.
func TestRewriteAbsolutePathsAddsPrefix(t *testing.T) {
	in := []byte(`<link href="/favicon.ico"><script src="/_app/immutable/entry.js"></script>` +
		`<img src="/assets/logo.png"><a href="/albums">x</a>`)
	got := string(rewriteAbsolutePaths(in, "/s/abc"))
	for _, want := range []string{
		`href="/s/abc/favicon.ico"`,
		`src="/s/abc/_app/immutable/entry.js"`,
		`src="/s/abc/assets/logo.png"`,
		`href="/s/abc/albums"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
}

// Only same-origin absolute paths are rewritten. Protocol-relative and absolute
// URLs belong to other hosts and must be left exactly as they are.
func TestRewriteAbsolutePathsLeavesExternalAlone(t *testing.T) {
	in := []byte(`<script src="https://cdn.example.com/x.js"></script>` +
		`<img src="//cdn.example.com/y.png"><a href="mailto:a@b.c">m</a>` +
		`<a href="relative/page">r</a><a href="#anchor">a</a>`)
	got := string(rewriteAbsolutePaths(in, "/s/abc"))
	if got != string(in) {
		t.Errorf("external/relative refs were altered:\n got: %s\nwant: %s", got, in)
	}
}

// Rewriting must be idempotent — a path already under the prefix stays put.
func TestRewriteAbsolutePathsIdempotent(t *testing.T) {
	in := []byte(`<script src="/s/abc/app.js"></script>`)
	if got := string(rewriteAbsolutePaths(in, "/s/abc")); got != string(in) {
		t.Errorf("double-prefixed: %s", got)
	}
}

// The proxy maps /s/{id}/<rest> onto the upstream HOST ROOT, and a service's
// configured path is only its entry point. That matters because apps commonly
// redirect OUTSIDE their own subpath — a reverse proxy publishing Grafana at
// /g/ bounces to an auth portal at /cmlogin/login.php. Path-scoped proxying
// could not express that; host-root proxying can.
func TestRewriteLocationKeepsWholeHostInsideProxy(t *testing.T) {
	tgt := ServiceTarget{Scheme: "https", Host: "10.0.0.5", Port: 443, Path: "/g"}
	cases := map[string]string{
		"/g/":                       "/s/abc/g/",
		"/cmlogin/login.php?from=/g": "/s/abc/cmlogin/login.php?from=/g",
		"/other/page":               "/s/abc/other/page",
	}
	for in, want := range cases {
		if got := rewriteLocation(in, tgt, "/s/abc"); got != want {
			t.Errorf("rewriteLocation(%q) = %q, want %q", in, got, want)
		}
	}
}

// A redirect to the same HOST on a different port or scheme is still the same
// app behind our proxy (that Grafana case redirects https:443 → http:80), so it
// must be pulled back inside rather than handed to the browser — where it would
// be blocked as mixed content and render blank.
func TestRewriteLocationNormalisesSchemeAndPort(t *testing.T) {
	tgt := ServiceTarget{Scheme: "https", Host: "10.0.0.5", Port: 443, Path: "/g"}
	for _, in := range []string{
		"http://10.0.0.5/cmlogin/login.php",
		"https://10.0.0.5:443/cmlogin/login.php",
		"http://10.0.0.5:80/cmlogin/login.php",
	} {
		if got := rewriteLocation(in, tgt, "/s/abc"); got != "/s/abc/cmlogin/login.php" {
			t.Errorf("rewriteLocation(%q) = %q", in, got)
		}
	}
	// A genuinely different host is still left to the browser.
	if got := rewriteLocation("https://accounts.example.com/oauth", tgt, "/s/abc"); got != "https://accounts.example.com/oauth" {
		t.Errorf("off-host redirect rewritten: %q", got)
	}
}

// The URL handed to the browser must not carry a redundant default port — the
// user typed a plain https:// address and expects to see it back.
func TestBrowserURLOmitsDefaultPorts(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://pics.chezmoi.ca", "https://pics.chezmoi.ca"},
		{"http://nas.lan", "http://nas.lan"},
		{"https://nas.lan:8443", "https://nas.lan:8443"},
		{"http://10.0.0.5:8096", "http://10.0.0.5:8096"},
	}
	for _, c := range cases {
		tgt, err := resolveServiceTarget(config.ServiceEntry{URLOverride: c.url})
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if got := tgt.BrowserURL(); got != c.want {
			t.Errorf("%s → %q, want %q", c.url, got, c.want)
		}
		// The dial URL always keeps its explicit port.
		if !strings.Contains(tgt.BaseURL(), strconv.Itoa(tgt.Port)) {
			t.Errorf("%s: dial URL lost its port: %q", c.url, tgt.BaseURL())
		}
	}
}
