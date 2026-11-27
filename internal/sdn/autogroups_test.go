package sdn

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Lines in the shapes ET Open, Etnetera and abuse.ch ship (trimmed).
const idsAutoRulesSample = `# a comment
alert ip [101.32.126.162,101.33.68.140] any -> $HOME_NET any (msg:"ET COMPROMISED Known Compromised or Hostile Host Traffic group 1"; classtype:misc-attack; sid:2500000; rev:7817;)
alert ip [2.56.192.0/22,2.57.122.0/24,10.0.0.0/8] any -> $HOME_NET any (msg:"ET DROP Spamhaus DROP Listed Traffic Inbound group 1"; reference:url,www.spamhaus.org/drop/drop.txt; sid:2400000; rev:4903;)
# alert ip [1.14.3.170,1.145.16.243] any -> $HOME_NET any (msg:"ET CINS Active Threat Intelligence Poor Reputation IP group 1"; sid:2403300; rev:1;)
alert ip $HOME_NET any -> [162.243.103.246] any (msg:"ET CNC Feodo Tracker Reported CnC Server group 1"; reference:url,feodotracker.abuse.ch; sid:2404300; rev:8118;)
alert tcp [102.130.117.167,102.130.127.117] any -> $HOME_NET any (msg:"ET TOR Known Tor Exit Node Traffic group 1"; sid:2520000; rev:6450;)
alert tcp $HOME_NET any -> [50.16.16.211] 443 (msg:"Feodo Tracker: potential QakBot CnC Traffic detected"; reference:url, feodotracker.abuse.ch/browse/host/50.16.16.211/; sid:900513699; rev:1;)
alert ip [134.122.76.66] any -> $HOME_NET any (msg:"ETN AGGRESSIVE IPs Group 0"; sid:5000000; rev:1;)
alert ip any any -> [8.8.8.8] any (msg:"ET POLICY Dropbox.com Offsite File Backup in Use"; sid:1; rev:1;)
`

func TestParseIDSAutoLists(t *testing.T) {
	got := ParseIDSAutoLists(strings.NewReader(idsAutoRulesSample))
	want := map[string][]string{
		"ids-et-compromised": {"101.32.126.162", "101.33.68.140"},
		"ids-et-drop":        {"2.56.192.0/22", "2.57.122.0/24"}, // 10/8 cleaned away
		"ids-et-feodo":       {"162.243.103.246"},
		"ids-et-tor-exit":    {"102.130.117.167", "102.130.127.117"},
		"ids-abuse-feodo":    {"50.16.16.211"},
		"ids-etn-aggressive": {"134.122.76.66"},
	}
	if len(got) != len(want) {
		t.Fatalf("groups = %v", got)
	}
	for id, w := range want {
		if g := CleanAutoCIDRs(got[id]); !reflect.DeepEqual(g, w) {
			t.Errorf("%s = %v, want %v", id, g, w)
		}
	}
	if _, ok := got["ids-et-cins"]; ok {
		t.Error("a commented-out (disabled) rule must not count")
	}
	for id := range got {
		if AutoGroupByID(id) == nil {
			t.Errorf("%s is not in the catalog", id)
		}
	}
}

func TestCleanAutoCIDRs(t *testing.T) {
	var in []netip.Prefix
	for _, s := range []string{"5.0.0.0/16", "5.0.1.0/24", "5.0.1.7/32", "192.168.1.0/24", "0.0.0.0/8",
		"224.0.0.0/3", "8.8.8.8/32", "8.8.8.8/32", "100.64.1.0/24", "172.20.0.0/16", "1.2.3.0/24"} {
		in = append(in, netip.MustParsePrefix(s))
	}
	got := CleanAutoCIDRs(in)
	want := []string{"1.2.3.0/24", "5.0.0.0/16", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// a list containing a reserved range inside a bigger public block drops
	// the whole block (it could cover local networks)
	if g := CleanAutoCIDRs([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); len(g) != 0 {
		t.Fatalf("0.0.0.0/0 must be dropped, got %v", g)
	}
}

func TestAutoSetName(t *testing.T) {
	if n := AutoSetName("ids-et-cins"); n != "a_ids_et_cins" {
		t.Fatal(n)
	}
	seen := map[string]string{}
	for _, d := range AutoGroupCatalog {
		n := AutoSetName(d.ID)
		if o, dup := seen[n]; dup {
			t.Fatalf("%s and %s share set %s", d.ID, o, n)
		}
		seen[n] = d.ID
	}
}

func autoEnv() Env {
	e := testEnv
	e.AutoGroupCIDRs = func(id string) ([]string, error) {
		switch id {
		case "fw-spamhaus-drop":
			return []string{"2.56.192.0/22", "5.5.5.5"}, nil
		}
		return nil, errors.New("not available")
	}
	return e
}

func TestCompile_AutoGroups(t *testing.T) {
	c := routerSample()
	c.Rules = append([]Rule{
		{ID: "ra000001", Enabled: true, Interface: "if000001", Action: "block", Protocol: "any",
			Source: Endpoint{Type: "auto", Value: "fw-spamhaus-drop"}, Destination: Endpoint{Type: "any"}, Description: "drop spamhaus"},
		{ID: "ra000002", Enabled: true, Interface: "", Action: "block", Protocol: "any",
			Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "auto", Value: "ids-et-feodo"}, Description: "no botnet C2"},
		{ID: "ra000003", Enabled: false, Interface: "", Action: "block", Protocol: "any",
			Source: Endpoint{Type: "auto", Value: "ids-et-cins"}, Destination: Endpoint{Type: "any"}, Description: "disabled: no set"},
	}, c.Rules...)
	got, err := Compile(c, autoEnv())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set a_fw_spamhaus_drop {", "elements = { 2.56.192.0/22, 5.5.5.5 }",
		"set a_ids_et_feodo {", // unavailable: declared, empty
		"ip saddr @a_fw_spamhaus_drop", "ip daddr @a_ids_et_feodo",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	feodo := got[strings.Index(got, "set a_ids_et_feodo {"):]
	feodo = feodo[:strings.Index(feodo, "}")]
	if strings.Contains(feodo, "elements") {
		t.Fatalf("an unavailable list must compile to an empty set:\n%s", feodo)
	}
	if strings.Contains(got, "a_ids_et_cins") {
		t.Fatal("a disabled rule must not declare its auto set")
	}
	// no environment at all still compiles (empty sets)
	if _, err := Compile(c, testEnv); err != nil {
		t.Fatalf("missing lists must never fail the compile: %v", err)
	}
}

func TestValidate_AutoGroups(t *testing.T) {
	c := routerSample()
	c.Rules = append(c.Rules, Rule{ID: "ra000009", Enabled: true, Interface: "if000001", Action: "block", Protocol: "any",
		Source: Endpoint{Type: "auto", Value: "fw-tor-exit", Not: true}, Destination: Endpoint{Type: "any"}})
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be inverted") {
		t.Fatalf("inverted auto group must be refused, got %v", err)
	}
	c.Rules[len(c.Rules)-1].Source = Endpoint{Type: "auto", Value: "nope"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unknown auto group must be refused, got %v", err)
	}
	c.Rules[len(c.Rules)-1].Source = Endpoint{Type: "auto", Value: "fw-tor-exit"}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid auto group refused: %v", err)
	}
}

func TestAutoSetRefreshScript(t *testing.T) {
	s := AutoSetRefreshScript("fw-tor-exit", []string{"1.2.3.4", "5.6.7.0/24"})
	want := "flush set ip znas_sdn a_fw_tor_exit\nadd element ip znas_sdn a_fw_tor_exit { 1.2.3.4, 5.6.7.0/24 }\n"
	if s != want {
		t.Fatalf("got %q", s)
	}
	if s := AutoSetRefreshScript("fw-tor-exit", nil); strings.Contains(s, "add element") {
		t.Fatalf("empty list must only flush: %q", s)
	}
}
