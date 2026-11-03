package sdn

// Dynamic DNS (Firewall → Dynamic DNS): ddclient keeps names at a DNS
// provider pointed at a gateway's public address. Each entry belongs to one
// gateway and follows that gateway's own address — not whichever link is
// carrying traffic — so every Internet link can have its own name.

import (
	"fmt"
	"strings"
)

// DDNSEntry is one set of names updated at one provider for one gateway.
type DDNSEntry struct {
	ID          string   `json:"id"`
	Enabled     bool     `json:"enabled"`
	Gateway     string   `json:"gateway"`  // gateway id
	Provider    string   `json:"provider"` // DDNSProviders key
	Hostnames   []string `json:"hostnames"`
	Login       string   `json:"login,omitempty"`
	Password    string   `json:"password,omitempty"` // password or API token
	PasswordSet bool     `json:"password_set,omitempty"`
	Zone        string   `json:"zone,omitempty"`   // Cloudflare
	Server      string   `json:"server,omitempty"` // custom (dyndns2) provider: host[:port], always HTTPS
	// IPSource: "" = the address of the gateway's interface; "web" = the
	// address the Internet sees (a modem doing NAT in front of this server).
	IPSource    string `json:"ip_source,omitempty"`
	Description string `json:"description,omitempty"`
}

// DDNSProvider describes how a provider is configured in ddclient.
type DDNSProvider struct {
	Protocol string
	Server   string
	NeedUser bool   // login asked (else fixed or unused)
	Login    string // fixed login (Cloudflare API tokens)
	Suffix   string // stripped from host names (DuckDNS wants the sub-name)
}

// DDNSProviders: the providers offered in the editor.
var DDNSProviders = map[string]DDNSProvider{
	"cloudflare": {Protocol: "cloudflare", Login: "token"},
	"duckdns":    {Protocol: "duckdns", Suffix: ".duckdns.org"},
	"noip":       {Protocol: "dyndns2", Server: "dynupdate.no-ip.com", NeedUser: true},
	"dyn":        {Protocol: "dyndns2", Server: "members.dyndns.org", NeedUser: true},
	"namecheap":  {Protocol: "namecheap", Server: "dynamicdns.park-your-domain.com", NeedUser: true},
	"ovh":        {Protocol: "dyndns2", Server: "www.ovh.com", NeedUser: true},
	"custom":     {Protocol: "dyndns2", NeedUser: true},
}

func (c *Config) normalizeDDNS() {
	if c.DDNS == nil {
		c.DDNS = []DDNSEntry{}
	}
	for i := range c.DDNS {
		e := &c.DDNS[i]
		hs := []string{}
		for _, h := range e.Hostnames {
			if h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")); h != "" {
				hs = append(hs, h)
			}
		}
		e.Hostnames = hs
		e.Zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(e.Zone), "."))
		// ddclient's ssl is global (always on): a scheme adds nothing.
		e.Server = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(e.Server), "https://"), "http://"), "/")
		e.Login = strings.TrimSpace(e.Login)
	}
}

// ddclientSafe: values are written single-quoted; a quote, backslash or
// line break would end them early.
func ddclientSafe(s string) bool { return !strings.ContainsAny(s, "'\\\n\r") }

func (c *Config) validateDDNS(add func(path, format string, a ...any)) {
	seen := map[string]bool{}
	for i, e := range c.DDNS {
		p := fmt.Sprintf("ddns[%d]", i)
		pv, ok := DDNSProviders[e.Provider]
		if !ok {
			add(p+".provider", "choose a dynamic DNS provider")
			continue
		}
		gw := c.GatewayByID(e.Gateway)
		if gw == nil || c.InterfaceByID(gw.Interface) == nil {
			add(p+".gateway", "dynamic DNS: its gateway no longer exists")
		}
		if e.IPSource != "" && e.IPSource != "web" {
			add(p+".ip_source", "choose where the public address comes from")
		}
		if len(e.Hostnames) == 0 {
			add(p+".hostnames", "enter at least one host name")
		}
		for _, h := range e.Hostnames {
			if seen[h] {
				add(p+".hostnames", "%s is already updated by another dynamic DNS entry", h)
				break
			}
			seen[h] = true
			if !domainRe.MatchString(h) {
				add(p+".hostnames", "%q is not a valid host name", h)
				break
			}
			if e.Provider == "cloudflare" && e.Zone != "" && h != e.Zone && !strings.HasSuffix(h, "."+e.Zone) {
				add(p+".hostnames", "%s is not in the zone %s", h, e.Zone)
				break
			}
		}
		if e.Password == "" && !e.PasswordSet {
			add(p+".password", "enter the password or token")
		}
		if !ddclientSafe(e.Password) || !ddclientSafe(e.Login) {
			add(p+".password", "the user name and password cannot contain a quote, backslash or line break")
		}
		if pv.NeedUser && e.Login == "" {
			add(p+".login", "enter the user name")
		}
		switch e.Provider {
		case "cloudflare":
			if e.Zone == "" || !domainRe.MatchString(e.Zone) {
				add(p+".zone", "enter the Cloudflare zone (the domain, e.g. example.com)")
			}
		case "custom":
			if e.Server == "" || !hostPortOK(e.Server) {
				add(p+".server", "enter the update server (host or host:port)")
			}
		}
	}
}

// RenderDDClient returns ddclient's configuration ("" when nothing is
// updated). One line per entry: options before the names apply only to them.
func RenderDDClient(c *Config) string {
	var b strings.Builder
	n := 0
	for _, e := range c.DDNS {
		pv, ok := DDNSProviders[e.Provider]
		gw := c.GatewayByID(e.Gateway)
		if !e.Enabled || !ok || gw == nil || len(e.Hostnames) == 0 {
			continue
		}
		in := c.InterfaceByID(gw.Interface)
		if in == nil || in.Disabled {
			continue
		}
		if n == 0 {
			b.WriteString("# Written by ZNAS (Firewall → Dynamic DNS); rewritten at every apply.\n")
			b.WriteString("daemon=300\nmin-error-interval=60\nsyslog=yes\nssl=yes\n\n")
		}
		n++
		if e.Description != "" {
			fmt.Fprintf(&b, "# %s\n", strings.ReplaceAll(e.Description, "\n", " "))
		}
		opts := []string{}
		if e.IPSource == "web" {
			opts = append(opts, "usev4=webv4", "webv4=ipify-ipv4")
		} else {
			opts = append(opts, "usev4=ifv4", "ifv4="+in.L3Device())
		}
		opts = append(opts, "protocol="+pv.Protocol)
		server := pv.Server
		if e.Provider == "custom" {
			server = e.Server
		}
		if server != "" {
			opts = append(opts, "server="+server)
		}
		if e.Provider == "cloudflare" {
			opts = append(opts, "zone="+e.Zone)
		}
		switch {
		case pv.Login != "":
			opts = append(opts, "login="+pv.Login)
		case pv.NeedUser:
			opts = append(opts, "login='"+e.Login+"'")
		}
		opts = append(opts, "password='"+e.Password+"'")
		hosts := make([]string, len(e.Hostnames))
		for i, h := range e.Hostnames {
			hosts[i] = strings.TrimSuffix(h, pv.Suffix)
		}
		fmt.Fprintf(&b, "%s %s\n", strings.Join(opts, ", "), strings.Join(hosts, ","))
	}
	return b.String()
}

func summarizeDDNS(prev, next *Config) []string {
	m := func(c *Config) map[string]any {
		out := map[string]any{}
		for _, e := range c.DDNS {
			out[e.ID] = e
		}
		return out
	}
	return countChanges(m(prev), m(next), "dynamic DNS name")
}
