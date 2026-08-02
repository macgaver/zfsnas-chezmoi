package system

import (
	"net"
	"strconv"
	"testing"
)

func TestPickWebPortRanking(t *testing.T) {
	// An explicit label always wins, even over a known web port.
	if got := PickWebPort("0.0.0.0:32768->80/tcp", map[string]string{"znas.service.port": "9000"}); got != 9000 {
		t.Errorf("label ignored: got %d want 9000", got)
	}
	// A known web port beats an arbitrary lower one (5432 = postgres).
	if got := PickWebPort("0.0.0.0:5432->5432/tcp, 0.0.0.0:8096->8096/tcp", nil); got != 8096 {
		t.Errorf("known web port not preferred: got %d want 8096", got)
	}
	// Otherwise the lowest published port.
	if got := PickWebPort("0.0.0.0:9443->9443/tcp, 0.0.0.0:7000->7000/tcp", nil); got != 7000 {
		t.Errorf("lowest fallback wrong: got %d want 7000", got)
	}
	// Nothing published → 0; the UI renders such a service as non-openable.
	if got := PickWebPort("", nil); got != 0 {
		t.Errorf("want 0 for no ports, got %d", got)
	}
	// IPv6 / multi-binding forms must still parse.
	if got := PickWebPort(":::8080->80/tcp, 0.0.0.0:8080->80/tcp", nil); got != 8080 {
		t.Errorf("ipv6 binding not parsed: got %d", got)
	}
	// A garbage label falls through to port parsing rather than erroring.
	if got := PickWebPort("0.0.0.0:8096->8096/tcp", map[string]string{"znas.service.port": "abc"}); got != 8096 {
		t.Errorf("bad label not ignored: got %d", got)
	}
}

func TestServiceURLScheme(t *testing.T) {
	if got := ServiceURL("10.0.0.5", 8096, "", ""); got != "http://10.0.0.5:8096" {
		t.Errorf("got %q", got)
	}
	// 443/8443 imply https unless overridden.
	if got := ServiceURL("10.0.0.5", 8443, "", ""); got != "https://10.0.0.5:8443" {
		t.Errorf("got %q", got)
	}
	// Explicit scheme override wins over the port heuristic.
	if got := ServiceURL("10.0.0.5", 8443, "http", ""); got != "http://10.0.0.5:8443" {
		t.Errorf("scheme override ignored: got %q", got)
	}
	// Path is appended, normalised, and never double-slashed.
	if got := ServiceURL("10.0.0.5", 8096, "https", "/web"); got != "https://10.0.0.5:8096/web" {
		t.Errorf("got %q", got)
	}
	if got := ServiceURL("10.0.0.5", 8096, "", "web/"); got != "http://10.0.0.5:8096/web" {
		t.Errorf("path not normalised: got %q", got)
	}
}

// A compose stack must collapse to ONE service, represented by its web
// container — not one entry per container (web + db + redis).
func TestGroupServicesCollapsesStack(t *testing.T) {
	cs := []DockerContainer{
		{ID: "1", Name: "app-db-1", Image: "postgres", State: "running", Project: "app", Ports: "0.0.0.0:5432->5432/tcp"},
		{ID: "2", Name: "app-web-1", Image: "nginx", State: "running", Project: "app", Ports: "0.0.0.0:8080->80/tcp"},
		{ID: "3", Name: "app-redis-1", Image: "redis", State: "running", Project: "app", Ports: ""},
	}
	out := GroupServices(cs)
	if len(out) != 1 {
		t.Fatalf("want 1 service for a 3-container stack, got %d", len(out))
	}
	if out[0].Container != "app-web-1" {
		t.Errorf("wrong primary container elected: %q", out[0].Container)
	}
	if out[0].Port != 8080 {
		t.Errorf("wrong port: %d", out[0].Port)
	}
	if out[0].Project != "app" {
		t.Errorf("project lost: %q", out[0].Project)
	}
}

// Containers with no compose project each stand alone.
func TestGroupServicesStandalone(t *testing.T) {
	cs := []DockerContainer{
		{ID: "1", Name: "pihole", Image: "pihole", State: "running", Ports: "0.0.0.0:8081->80/tcp"},
		{ID: "2", Name: "watchtower", Image: "watchtower", State: "running", Ports: ""},
	}
	out := GroupServices(cs)
	if len(out) != 2 {
		t.Fatalf("want 2 standalone services, got %d", len(out))
	}
	for _, s := range out {
		if s.Project != "" {
			t.Errorf("standalone container got a project: %+v", s)
		}
	}
}

// A stack where no container publishes a port still yields one service, so the
// user can see and control it (it just isn't openable).
func TestGroupServicesStackWithoutPorts(t *testing.T) {
	cs := []DockerContainer{
		{ID: "1", Name: "job-worker-1", Image: "worker", State: "running", Project: "job"},
		{ID: "2", Name: "job-cron-1", Image: "cron", State: "running", Project: "job"},
	}
	out := GroupServices(cs)
	if len(out) != 1 {
		t.Fatalf("want 1 service, got %d", len(out))
	}
	if out[0].Port != 0 {
		t.Errorf("want port 0, got %d", out[0].Port)
	}
}

// Grouping must be deterministic — the elected container and ordering cannot
// vary between scans, or the UI would flicker and IDs would churn.
func TestGroupServicesIsDeterministic(t *testing.T) {
	cs := []DockerContainer{
		{ID: "1", Name: "s-b-1", Image: "b", State: "running", Project: "s", Ports: "0.0.0.0:8080->80/tcp"},
		{ID: "2", Name: "s-a-1", Image: "a", State: "running", Project: "s", Ports: "0.0.0.0:8081->80/tcp"},
	}
	first := GroupServices(cs)
	for i := 0; i < 5; i++ {
		got := GroupServices(cs)
		if len(got) != len(first) || got[0].Container != first[0].Container {
			t.Fatalf("non-deterministic election: %q vs %q", got[0].Container, first[0].Container)
		}
	}
}

// Address selection must be REACHABILITY-verified, not a guess.
//
// Real-world failure this fixes (observed on 192.168.2.5): an instance running
// Docker has several addresses — its LAN NIC, a second VLAN NIC, plus docker0
// and one bridge per compose network. Picking the "first" one is arbitrary: the
// same host produced 192.168.2.44 on one pass and 10.128.8.44 on the next, and
// only one of them is routable from the ZNAS host. Services silently pointed at
// an address that could never answer.
func TestPickReachableAddrPrefersOneThatAnswers(t *testing.T) {
	// Loopback is deliberately filtered out (a guest's 127.0.0.1 is never
	// reachable from the host), so the listener must sit on a real address.
	local := firstNonLoopbackIPv4(t)
	ln, err := net.Listen("tcp", net.JoinHostPort(local, "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", local, err)
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// 192.0.2.1 is TEST-NET-1 — guaranteed not to answer. It is listed FIRST,
	// so a passing test proves we skipped past a dead candidate.
	got, ok := PickReachableAddr([]string{"192.0.2.1", local}, port)
	if !ok || got != local {
		t.Errorf("want the address that answers (%s), got %q ok=%v", local, got, ok)
	}
}

func firstNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip("cannot enumerate interfaces")
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 available")
	return ""
}

// When nothing answers we must say so rather than inventing a URL that will
// only fail later inside the panel.
func TestPickReachableAddrReportsUnreachable(t *testing.T) {
	if got, ok := PickReachableAddr([]string{"192.0.2.1", "192.0.2.2"}, 65000); ok {
		t.Errorf("want ok=false when nothing answers, got %q", got)
	}
}

// No candidates and no port are both "unreachable", never a panic.
func TestPickReachableAddrEdgeCases(t *testing.T) {
	if _, ok := PickReachableAddr(nil, 8080); ok {
		t.Error("no candidates must not report reachable")
	}
	if _, ok := PickReachableAddr([]string{"10.0.0.1"}, 0); ok {
		t.Error("port 0 must not report reachable")
	}
}

// Docker's own bridge addresses are never the right answer: they exist INSIDE
// the guest, so the host cannot route to them.
func TestFilterCandidateAddrsDropsDockerBridges(t *testing.T) {
	in := []string{"127.0.0.1", "172.17.0.1", "172.18.0.1", "192.168.2.8", "10.128.8.8", "172.20.0.1"}
	got := FilterCandidateAddrs(in)
	for _, bad := range []string{"127.0.0.1", "172.17.0.1", "172.18.0.1", "172.20.0.1"} {
		for _, g := range got {
			if g == bad {
				t.Errorf("candidate %q should have been filtered out: %v", bad, got)
			}
		}
	}
	if len(got) != 2 || got[0] != "192.168.2.8" {
		t.Errorf("want the real NIC addresses first, got %v", got)
	}
}
