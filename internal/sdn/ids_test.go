package sdn

import (
	"strings"
	"testing"
)

func idsSample() *Config {
	c := twoWAN()
	c.IDS = IDSSettings{Enabled: true, Sources: []string{"abuse.ch/sslbl-c2"}, AlertSeverity: 2,
		Suppressed: []IDSSuppress{{SID: 2013028}, {SID: 2210054, IP: "10.128.8.8"}}}
	c.Normalize()
	return c
}

func TestIDS_DefaultsWhenNeverSet(t *testing.T) {
	c := twoWAN()
	c.IDS.Enabled = true
	c.Normalize()
	if strings.Join(c.IDS.Categories, ",") != "emerging-exploit,emerging-malware,compromised,drop,botcc" {
		t.Fatalf("default categories %v", c.IDS.Categories)
	}
	// An explicitly emptied list stays empty.
	c.IDS.Categories = []string{}
	c.Normalize()
	if len(c.IDS.Categories) != 0 {
		t.Fatal("an empty choice was replaced by the defaults")
	}
}

func TestIDS_Validation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *Config)
		path   string
	}{
		{"unknown iface", func(c *Config) { c.IDS.Interfaces = []string{"nope"} }, "ids.interfaces"},
		{"commercial source", func(c *Config) { c.IDS.Sources = []string{"et/pro"} }, "ids.sources"},
		{"bad category", func(c *Config) { c.IDS.Categories = []string{"../x"} }, "ids.categories"},
		{"bad severity", func(c *Config) { c.IDS.AlertSeverity = 4 }, "ids.alert_severity"},
		{"bad sid", func(c *Config) { c.IDS.Suppressed[0].SID = 0 }, "ids.suppressed[0].sid"},
		{"bad suppress ip", func(c *Config) { c.IDS.Suppressed[1].IP = "x" }, "ids.suppressed[1].ip"},
		{"no wan to watch", func(c *Config) {
			for i := range c.Interfaces {
				c.Interfaces[i].Role = "lan"
			}
			c.Gateways, c.PortForwards, c.SNATRules = nil, nil, nil
		}, "ids.interfaces"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := idsSample()
			tc.mutate(c)
			c.Normalize()
			if e := onlyErr(t, c); e.Path != tc.path {
				t.Fatalf("path %q (%s), want %q", e.Path, e.Message, tc.path)
			}
		})
	}
	if err := idsSample().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestIDS_InterfacesDefaultToWANs(t *testing.T) {
	devs := idsSample().IDSDevices()
	if strings.Join(devs, ",") != "ppp-ifpppoe1" {
		t.Fatalf("watched devices %v", devs)
	}
	c := idsSample()
	c.IDS.Interfaces = []string{"if000800", "ifpppoe1"}
	if got := strings.Join(c.IDSDevices(), ","); got != "br-enp2s0-v800,ppp-ifpppoe1" {
		t.Fatalf("chosen devices %v", got)
	}
}

func TestRenderSuricataYAML(t *testing.T) {
	golden(t, "suricata.yaml", RenderSuricataYAML(idsSample(), IDSPaths{
		RulesDir: "/labpool/znas-netstats/suricata/rules", LogDir: "/run/znas-sdn-ids", Socket: "/opt/zfsnas/config/sdn/ids-eve.sock",
		Threshold: "/etc/znas-sdn/threshold.config"}))
}

func TestRenderSuricataYAML_HomeNetFallback(t *testing.T) {
	c := idsSample()
	for i := range c.Interfaces {
		if c.Interfaces[i].Role == "lan" {
			c.Interfaces[i].IPv4Mode, c.Interfaces[i].IPv4 = "dhcp", ""
		}
	}
	got := RenderSuricataYAML(c, IDSPaths{})
	if !strings.Contains(got, `HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"`) {
		t.Fatalf("no RFC1918 fallback:\n%s", got)
	}
}

func TestRenderThreshold(t *testing.T) {
	got := RenderThreshold(idsSample())
	want := "# Managed by ZNAS Firewall\nsuppress gen_id 1, sig_id 2013028\nsuppress gen_id 1, sig_id 2210054, track by_either, ip 10.128.8.8\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderDisableConf(t *testing.T) {
	groups := []string{"botcc", "botcc.portgrouped", "emerging-games", "emerging-malware", "tor", "drop"}
	got := RenderDisableConf(idsSample(), groups)
	want := "# Managed by ZNAS Firewall: ET Open groups not chosen\ngroup:botcc.portgrouped\ngroup:emerging-games\ngroup:tor\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSummarize_IDS(t *testing.T) {
	prev, next := idsSample(), idsSample()
	next.IDS.Suppressed = next.IDS.Suppressed[:1]
	if got := Summarize(prev, next); !strings.Contains(got, "intrusion detection edited") {
		t.Fatalf("summary %q", got)
	}
	next = idsSample()
	next.IDS.Enabled = false
	if got := Summarize(prev, next); !strings.Contains(got, "intrusion detection off") {
		t.Fatalf("summary %q", got)
	}
}
