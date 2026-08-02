package handlers

import "testing"

// The service proxy lives at /s/{id}/ — neither /api/ nor /ws/ — so the
// "everything else is local" rule at the end of isRelayBypassed swallowed it.
// While viewing an InterLink peer, the service ids come from THAT peer, so a
// locally-served /s/ request looks them up in the wrong services.json and
// answers "service not found" for every embedded app on a peer.
func TestServiceProxyIsRelayForwarded(t *testing.T) {
	for _, p := range []string{
		"/s/6d17c3f0c13f977d/",
		"/s/6d17c3f0c13f977d/web/index.html",
		"/s/abc/api/login?next=/x",
	} {
		if isRelayBypassed(p) {
			t.Errorf("%s must be forwarded to the viewed peer, not served locally", p)
		}
	}
}

// The rule it rides on must stay intact: SPA routes, static assets and the
// login page are still local.
func TestRelayBypassStillLocalForSPA(t *testing.T) {
	for _, p := range []string{
		"/", "/login", "/static/app.js", "/setup",
		"/api/auth/login", "/api/interlink/servers", "/ws/alerts",
	} {
		if !isRelayBypassed(p) {
			t.Errorf("%s must stay local", p)
		}
	}
}

// Guard against a lookalike path being caught by the new rule.
func TestRelayBypassDoesNotOvermatch(t *testing.T) {
	for _, p := range []string{"/static/x", "/setup"} {
		if !isRelayBypassed(p) {
			t.Errorf("%s should be local", p)
		}
	}
}
