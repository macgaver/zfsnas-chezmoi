package sdn

import (
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

var testEnv = Env{PortalPorts: []int{8443}, SSHPort: 22}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		_ = os.MkdirAll("testdata", 0755)
		if err := os.WriteFile(p, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("missing golden %s (run with -update): %v", p, err)
	}
	if string(want) != got {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// routerSample is the owner sample in router mode with the rule mix the
// golden file exercises.
func routerSample() *Config {
	c := ownerSample()
	c.Interfaces = []Interface{c.Interfaces[0], c.Interfaces[3], c.Interfaces[4]} // LAN, VLAN700, VLAN800
	c.Rules = append(c.Rules,
		Rule{ID: "r0000003", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "any",
			Source: Endpoint{Type: "iface_net", Value: "if000001"}, Destination: Endpoint{Type: "group", Value: "g0000001", Not: true},
			Description: "VLAN192 ok internet"},
		Rule{ID: "r0000004", Enabled: true, Interface: "", Action: "block", Protocol: "any",
			Source: Endpoint{Type: "cidr", Value: "203.0.113.0/24"}, Destination: Endpoint{Type: "any"}, Log: true,
			Description: "block bad net"},
		Rule{ID: "r0000005", Enabled: true, Interface: "if000800", Action: "allow", Protocol: "udp",
			Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "this_znas"}, DstPorts: "group:g0000002",
			Description: "game to znas"},
		Rule{ID: "r0000006", Enabled: false, Interface: "if000800", Action: "allow", Protocol: "tcp",
			Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, DstPorts: "80,443",
			Description: "disabled rule"},
	)
	return c
}

func TestCompile_Monitor(t *testing.T) {
	c := routerSample()
	c.Settings.Mode = "monitor"
	got, err := Compile(c, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "compile_monitor.nft", got)
	if strings.Contains(got, "default-deny") {
		t.Fatal("monitor mode must not drop")
	}
}

func TestCompile_RouterOwnerSample(t *testing.T) {
	got, err := Compile(routerSample(), testEnv)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "compile_router.nft", got)
}

func chainBody(script, chain string) string {
	i := strings.Index(script, "\tchain "+chain+" {")
	if i < 0 {
		return ""
	}
	rest := script[i:]
	return rest[:strings.Index(rest, "\n\t}")]
}

func TestCompile_AntiLockoutFirst(t *testing.T) {
	got, _ := Compile(routerSample(), testEnv)
	in := chainBody(got, "input")
	a, j := strings.Index(in, `comment "anti-lockout"`), strings.Index(in, "jump ")
	if a < 0 || j < 0 || a > j {
		t.Fatalf("anti-lockout must precede the first jump:\n%s", in)
	}
	if !strings.Contains(in, `iifname "enp1s0" tcp dport { 22, 8443 } accept`) {
		t.Fatalf("anti-lockout line wrong:\n%s", in)
	}
	c := routerSample()
	c.Settings.AntiLockout = false
	got, _ = Compile(c, testEnv)
	if strings.Contains(got, "anti-lockout") {
		t.Fatal("anti-lockout present while disabled")
	}
}

func TestCompile_ThisZNASOnlyInput(t *testing.T) {
	got, _ := Compile(routerSample(), testEnv)
	if !strings.Contains(chainBody(got, "in_if000800"), `comment "r:r0000005"`) {
		t.Fatal("this_znas rule missing from input chain")
	}
	if strings.Contains(chainBody(got, "fw_if000800"), `r:r0000005`) {
		t.Fatal("this_znas rule must not be in forward chain")
	}
}

func TestCompile_DisabledRuleOmitted(t *testing.T) {
	got, _ := Compile(routerSample(), testEnv)
	if strings.Contains(got, "r0000006") {
		t.Fatal("disabled rule compiled")
	}
}

func TestCompile_RejectsInvalid(t *testing.T) {
	c := routerSample()
	c.Rules[0].Source = Endpoint{Type: "group", Value: "nope"}
	_, err := Compile(c, testEnv)
	var ve ValidationErrors
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationErrors, got %v", err)
	}
}

func TestSafeModeRuleset(t *testing.T) {
	got := SafeModeRuleset(routerSample(), testEnv)
	golden(t, "safemode.nft", got)
	if strings.Contains(got, "jump") {
		t.Fatal("safe mode must not reference rule chains")
	}
	got = SafeModeRuleset(nil, testEnv)
	if !strings.Contains(got, "tcp dport { 22, 8443 } accept") || !strings.Contains(got, "policy drop") {
		t.Fatalf("nil-config safe mode wrong:\n%s", got)
	}
}

// TestCompile_NftCheck asks the real nft to parse the goldens. Runs only on
// a machine with nft and root (the lab VM): ZNAS_NFT_CHECK=1.
func TestCompile_NftCheck(t *testing.T) {
	if os.Getenv("ZNAS_NFT_CHECK") != "1" {
		t.Skip("set ZNAS_NFT_CHECK=1 on a host with nft")
	}
	for _, f := range []string{"compile_monitor.nft", "compile_router.nft", "safemode.nft"} {
		out, err := exec.Command("nft", "-c", "-f", filepath.Join("testdata", f)).CombinedOutput()
		if err != nil {
			t.Fatalf("nft -c %s: %v\n%s", f, err, out)
		}
	}
}

// Port forwards to Incus instances (NAT proxy devices) and Docker published
// ports arrive as new, DNAT'd connections on a managed interface: until the
// SDN NAT page owns them (phase 3) they must not hit default-deny.
func TestCompile_ForwardAcceptsDNAT(t *testing.T) {
	got, _ := Compile(routerSample(), testEnv)
	fw := chainBody(got, "forward")
	d, j := strings.Index(fw, "ct status dnat accept"), strings.Index(fw, "jump ")
	if d < 0 || d > j {
		t.Fatalf("forward chain must accept DNAT'd flows before the rule chains:\n%s", fw)
	}
}

func countryEnv() Env {
	e := testEnv
	e.CountryCIDRs = func(cc string) ([]string, error) {
		return map[string][]string{"CA": {"24.48.0.0/16"}, "US": {"8.8.8.0/24", "140.82.112.0/20"}, "SE": {"89.160.20.0/23"}}[cc], nil
	}
	return e
}

func TestCompile_CountrySets(t *testing.T) {
	c := routerSample()
	c.Groups = append(c.Groups, Group{ID: "gcountry1", Name: "OKCOUNTRIES", Kind: "countries", Members: []string{"CA", "US"}})
	c.Rules = append(c.Rules,
		Rule{ID: "rc000001", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "tcp", Source: Endpoint{Type: "group", Value: "gcountry1"},
			Destination: Endpoint{Type: "any"}, DstPorts: "443", Description: "ok 443 from OKCOUNTRIES"},
		Rule{ID: "rc000002", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "udp", Source: Endpoint{Type: "countries", Value: "SE"},
			Destination: Endpoint{Type: "this_znas"}, DstPorts: "51820", Description: "wireguard from Sweden"},
		Rule{ID: "rc000003", Enabled: true, Interface: "if000001", Action: "block", Protocol: "any", Source: Endpoint{Type: "countries", Value: "CA,US", Not: true},
			Destination: Endpoint{Type: "any"}, Description: "block outside CA+US"},
	)
	got, err := Compile(c, countryEnv())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"set c_gcountry1 {", "elements = { 24.48.0.0/16, 8.8.8.0/24, 140.82.112.0/20 }",
		"set c_se {", "ip saddr @c_gcountry1 th dport 443",
		"set c_ca_us {", "ip saddr != @c_ca_us",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
}

func TestCompile_CountryDBMissing(t *testing.T) {
	c := routerSample()
	c.Rules = append(c.Rules, Rule{ID: "rc000002", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "any",
		Source: Endpoint{Type: "countries", Value: "SE"}, Destination: Endpoint{Type: "any"}})
	if _, err := Compile(c, testEnv); err == nil || !strings.Contains(err.Error(), "country database") {
		t.Fatalf("missing country DB must fail the compile: %v", err)
	}
	e := testEnv
	e.CountryCIDRs = func(string) ([]string, error) { return nil, errors.New("country database not available") }
	if _, err := Compile(c, e); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidate_Countries(t *testing.T) {
	c := ownerSample()
	c.Groups = append(c.Groups, Group{ID: "gc1", Name: "bad", Kind: "countries", Members: []string{"XX"}})
	if fe := onlyErr(t, c); fe.Path != "groups[2].members[0]" {
		t.Fatalf("%v", fe)
	}
	c = ownerSample()
	c.Rules[0].Source = Endpoint{Type: "countries", Value: "se"}
	if fe := onlyErr(t, c); fe.Path != "rules[0].source" {
		t.Fatalf("%v", fe)
	}
	if CountryName("SE") != "Sweden" || CountryName("CA") != "Canada" {
		t.Fatal("country names")
	}
}

func TestCompile_BlockedCounting(t *testing.T) {
	got, _ := Compile(routerSample(), testEnv)
	if !strings.Contains(got, "\tset blk {\n\t\ttype ipv4_addr . inet_proto . inet_service . ifname . mark\n\t\tflags dynamic,timeout\n\t\ttimeout 15m\n\t\tsize 65536\n\t\tcounter\n\t}") {
		t.Fatalf("blk set missing:\n%s", got)
	}
	in := chainBody(got, "input")
	if !strings.Contains(in, "meta l4proto { tcp, udp } update @blk { ip saddr . meta l4proto . th dport . iifname . 0x0 }\n") ||
		!strings.Contains(in, "meta l4proto != { tcp, udp } update @blk { ip saddr . meta l4proto . 0 . iifname . 0x0 }\n") {
		t.Fatalf("default deny does not count:\n%s", in)
	}
	nums := BlockRuleNumbers(routerSample())
	if nums[1] != "r0000002" || nums[2] != "r0000004" {
		t.Fatalf("numbers %v", nums)
	}
	any := chainBody(got, "any_in")
	if !strings.Contains(any, "update @blk { ip saddr . meta l4proto . th dport . iifname . 0x2 }") || !strings.Contains(any, "update @blk { ip saddr . meta l4proto . 0 . iifname . 0x2 }") {
		t.Fatalf("block rule does not count:\n%s", any)
	}
	c := routerSample()
	c.Settings.Mode = "monitor"
	if got, _ := Compile(c, testEnv); strings.Contains(got, "update @blk") {
		t.Fatal("monitor mode blocks nothing, counts nothing")
	}
}

// When the blk set is full the kernel skips the REST OF THE RULE holding the
// failed update: a verdict on the same line would be skipped too and the
// packet accepted. Counting must never share a line with a verdict.
func TestCompile_BlkUpdateNeverCarriesVerdict(t *testing.T) {
	c := routerSample()
	c.Rules = append(c.Rules, Rule{ID: "rtcpud01", Enabled: true, Interface: "if000001", Action: "reject", Protocol: "tcpudp",
		Source: Endpoint{Type: "any"}, Destination: Endpoint{Type: "any"}, DstPorts: "25"})
	got, _ := Compile(c, testEnv)
	lines := strings.Split(got, "\n")
	for i, l := range lines {
		if !strings.Contains(l, "update @blk") {
			continue
		}
		for _, v := range []string{" accept", " drop", " reject"} {
			if strings.Contains(l, v) {
				t.Fatalf("line %d carries a verdict with the update:\n%s", i, l)
			}
		}
	}
	for _, ch := range []string{"input", "forward"} {
		body := chainBody(got, ch)
		if !strings.HasSuffix(strings.TrimSpace(body), `counter drop comment "default-deny"`) {
			t.Fatalf("%s must end with an unconditional drop:\n%s", ch, body)
		}
	}
	// every rule chain line with an update is followed by its verdict line
	any := chainBody(got, "any_in")
	if strings.Count(any, `drop comment "r:r0000004"`) < 1 {
		t.Fatalf("block rule lost its drop:\n%s", any)
	}
}

func TestCompile_CountrySetEdgeCases(t *testing.T) {
	c := routerSample()
	c.Rules = append(c.Rules, Rule{ID: "rcempty1", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "any",
		Source: Endpoint{Type: "countries", Value: "AQ"}, Destination: Endpoint{Type: "any"}, Description: "antarctica"})
	e := testEnv
	e.CountryCIDRs = func(string) ([]string, error) { return nil, nil }
	if _, err := Compile(c, e); err == nil || !strings.Contains(err.Error(), "no known networks") {
		t.Fatalf("an empty country set must be an error: %v", err)
	}
	var codes []string
	for _, cc := range Countries[:120] {
		codes = append(codes, cc[0])
	}
	c = routerSample()
	c.Rules = append(c.Rules, Rule{ID: "rcmany01", Enabled: true, Interface: "if000001", Action: "allow", Protocol: "any",
		Source: Endpoint{Type: "countries", Value: strings.Join(codes, ",")}, Destination: Endpoint{Type: "any"}})
	e.CountryCIDRs = func(string) ([]string, error) { return []string{"1.2.3.0/24"}, nil }
	got, err := Compile(c, e)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "set c_") && len(strings.Fields(l)[1]) > 64 {
			t.Fatalf("set name too long: %s", l)
		}
	}
}
