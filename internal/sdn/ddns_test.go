package sdn

import (
	"strings"
	"testing"
)

func ddnsSample() *Config {
	c := twoWAN()
	c.DDNS = []DDNSEntry{
		{ID: "dd000001", Enabled: true, Gateway: "gwpppoe1", Provider: "cloudflare", Zone: "example.com",
			Hostnames: []string{"home.example.com", "vpn.example.com"}, Password: "cf-token", Description: "Main"},
		{ID: "dd000002", Enabled: true, Gateway: "gwrouter", Provider: "duckdns", Hostnames: []string{"myhome.duckdns.org"},
			Password: "duck-token", IPSource: "web"},
		{ID: "dd000003", Enabled: false, Gateway: "gwpppoe1", Provider: "noip", Hostnames: []string{"x.ddns.net"}, Login: "me@example.com", Password: "p"},
	}
	c.Normalize()
	return c
}

// One ddclient line per entry: the gateway's own interface address (or the
// address seen from the Internet), the provider's settings, then the names.
func TestRenderDDClient(t *testing.T) {
	got := RenderDDClient(ddnsSample())
	for _, want := range []string{
		"daemon=300\n",
		"min-error-interval=60\n", // a failed update may be tried again soon
		"usev4=ifv4, ifv4=ppp-ifpppoe1, protocol=cloudflare, zone=example.com, login=token, password='cf-token' home.example.com,vpn.example.com\n",
		"usev4=webv4, webv4=ipify-ipv4, protocol=duckdns, password='duck-token' myhome\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "x.ddns.net") {
		t.Errorf("disabled entry rendered:\n%s", got)
	}

	c := ddnsSample()
	c.DDNS = []DDNSEntry{
		{ID: "a", Enabled: true, Gateway: "gwrouter", Provider: "noip", Hostnames: []string{"x.ddns.net"}, Login: "me@example.com", Password: "p,w"},
		{ID: "b", Enabled: true, Gateway: "gwrouter", Provider: "custom", Server: "dyn.example.net:8080", Hostnames: []string{"h.example.net"}, Login: "u", Password: "p"},
		{ID: "c", Enabled: true, Gateway: "gwrouter", Provider: "namecheap", Hostnames: []string{"www.example.org"}, Login: "example.org", Password: "nc"},
	}
	got = RenderDDClient(c)
	for _, want := range []string{
		"usev4=ifv4, ifv4=enp1s0, protocol=dyndns2, server=dynupdate.no-ip.com, login='me@example.com', password='p,w' x.ddns.net\n",
		"usev4=ifv4, ifv4=enp1s0, protocol=dyndns2, server=dyn.example.net:8080, login='u', password='p' h.example.net\n",
		"usev4=ifv4, ifv4=enp1s0, protocol=namecheap, server=dynamicdns.park-your-domain.com, login='example.org', password='nc' www.example.org\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}

	c.DDNS = nil
	if got := RenderDDClient(c); got != "" {
		t.Fatalf("nothing to update must render nothing, got:\n%s", got)
	}
}

func TestDDNS_Validate(t *testing.T) {
	if err := ddnsSample().Validate(); err != nil {
		t.Fatalf("valid sample refused: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(e *DDNSEntry)
		want   string
	}{
		{"unknown gateway", func(e *DDNSEntry) { e.Gateway = "nope" }, "gateway"},
		{"unknown provider", func(e *DDNSEntry) { e.Provider = "acme" }, "provider"},
		{"no host name", func(e *DDNSEntry) { e.Hostnames = nil }, "host name"},
		{"bad host name", func(e *DDNSEntry) { e.Hostnames = []string{"bad name"} }, "host name"},
		{"no token", func(e *DDNSEntry) { e.Password = "" }, "token"},
		{"quote in the token", func(e *DDNSEntry) { e.Password = "a'b" }, "quote"},
		{"newline in the token", func(e *DDNSEntry) { e.Password = "a\nb" }, "quote"},
		{"cloudflare without zone", func(e *DDNSEntry) { e.Zone = "" }, "zone"},
		{"name outside the zone", func(e *DDNSEntry) { e.Hostnames = []string{"home.other.com"} }, "zone"},
		{"bad IP source", func(e *DDNSEntry) { e.IPSource = "magic" }, "address"},
	}
	for _, tc := range cases {
		c := ddnsSample()
		tc.mutate(&c.DDNS[0])
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", tc.name, tc.want, err)
		}
	}
	c := ddnsSample()
	c.DDNS[2].Login = ""
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "user name") {
		t.Errorf("No-IP without login: %v", err)
	}
	c = ddnsSample()
	c.DDNS[2] = DDNSEntry{ID: "dd000003", Enabled: true, Gateway: "gwrouter", Provider: "custom", Hostnames: []string{"h.example.net"}, Login: "u", Password: "p"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server") {
		t.Errorf("custom without server: %v", err)
	}
	// ddclient knows a name once: it cannot be in two entries
	c = ddnsSample()
	c.DDNS[1].Hostnames = []string{"vpn.example.com"}
	c.DDNS[1].Provider, c.DDNS[1].Zone = "cloudflare", "example.com"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "already updated") {
		t.Errorf("same name twice: %v", err)
	}
	// a gateway that goes away takes its entries' validity with it
	c = ddnsSample()
	c.Gateways = c.Gateways[1:]
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Errorf("entry of a removed gateway: %v", err)
	}
}

// The token never reaches the browser; an edit that does not send it back
// keeps the stored one.
func TestDDNS_Secrets(t *testing.T) {
	c := ddnsSample()
	r := c.Redacted()
	if r.DDNS[0].Password != "" || !r.DDNS[0].PasswordSet {
		t.Fatalf("token sent to the browser: %+v", r.DDNS[0])
	}
	r.DDNS[0].Hostnames = []string{"home.example.com"}
	r.KeepSecretsFrom(c)
	if r.DDNS[0].Password != "cf-token" || r.DDNS[0].PasswordSet {
		t.Fatalf("stored token lost: %+v", r.DDNS[0])
	}
}

func TestDDNS_Summary(t *testing.T) {
	prev := ddnsSample()
	next := ddnsSample()
	next.DDNS = append(next.DDNS[:1], next.DDNS[2:]...)
	next.DDNS[0].Hostnames = []string{"home.example.com"}
	got := Summarize(prev, next)
	if !strings.Contains(got, "-1 dynamic DNS name") || !strings.Contains(got, "1 dynamic DNS name edited") {
		t.Fatalf("summary %q", got)
	}
}
