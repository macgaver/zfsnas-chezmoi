package system

// Service discovery helpers (v6.8.1) — turning a raw docker/podman container
// list into the "applications" the Services tab shows.
//
// Two pure functions carry the interesting logic and are unit-tested without a
// runtime: PickWebPort (which port serves this app's UI?) and GroupServices
// (which containers are actually ONE application?). Design:
// PLANS/plan-version-6.8.1.md §4–§5.

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// knownWebPorts rank ahead of arbitrary published ports when guessing which
// port serves an app's web UI. Keeps a database's published port from being
// mistaken for the front end.
var knownWebPorts = map[int]bool{
	80: true, 443: true, 3000: true, 5000: true, 8000: true, 8080: true,
	8081: true, 8096: true, 8123: true, 8443: true, 9000: true,
}

// serviceLabelKeys are inspected, in order, for an explicit port declaration.
// Supporting the homepage.* label lets users who already annotate their compose
// files for gethomepage get correct ports here for free.
var serviceLabelKeys = []string{"znas.service.port", "homepage.port"}

// publishedPortRe extracts the HOST side of a docker/podman port mapping —
// "0.0.0.0:8096->8096/tcp" and ":::8096->8096/tcp" both yield 8096.
var publishedPortRe = regexp.MustCompile(`:(\d+)->\d+/tcp`)

// PublishedPorts returns every published host port, ascending.
func PublishedPorts(ports string) []int {
	seen := map[int]bool{}
	var out []int
	for _, m := range publishedPortRe.FindAllStringSubmatch(ports, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 || n > 65535 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// PickWebPort chooses the most likely web port from a formatted ports string.
// Ranking: explicit label → known web port → lowest published port.
// Returns 0 when nothing is published (the UI shows such a service as
// controllable but not openable).
// LabelPort returns the port a container explicitly declares by label, or 0
// when it declares none. An explicit declaration is the user's own statement
// about what this container serves, so it outranks every heuristic.
func LabelPort(labels map[string]string) int {
	for _, k := range serviceLabelKeys {
		if v, ok := labels[k]; ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n < 65536 {
				return n
			}
		}
	}
	return 0
}

func PickWebPort(ports string, labels map[string]string) int {
	if n := LabelPort(labels); n > 0 {
		return n
	}
	seen := map[int]bool{}
	var published []int
	for _, m := range publishedPortRe.FindAllStringSubmatch(ports, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 || n > 65535 || seen[n] {
			continue
		}
		seen[n] = true
		published = append(published, n)
	}
	if len(published) == 0 {
		return 0
	}
	sort.Ints(published)
	for _, p := range published {
		if knownWebPorts[p] {
			return p
		}
	}
	return published[0]
}

// ServiceURL builds an app's base URL. The scheme defaults to https for the
// conventional TLS ports and http otherwise; an explicit scheme always wins.
func ServiceURL(ip string, port int, scheme, path string) string {
	if scheme == "" {
		if port == 443 || port == 8443 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	u := scheme + "://" + ip + ":" + strconv.Itoa(port)
	if p := strings.Trim(strings.TrimSpace(path), "/"); p != "" {
		u += "/" + p
	}
	return u
}

// DiscoveredService is one application found inside an instance, after stack
// grouping. It is runtime-agnostic (docker and podman produce the same shape).
type DiscoveredService struct {
	Project     string // compose project ("" = standalone container)
	Container   string // elected primary container
	ContainerID string
	Image       string
	State       string // "running" | "exited" | …
	Port        int    // 0 = nothing published
	// AllPorts lists every published host port, so the UI can offer the real
	// choices instead of making the user guess when our pick is wrong.
	AllPorts []int
}

// EligibleForService reports whether a container should appear as an
// application. A standalone container that publishes no port has no URL,
// cannot be opened, and is overwhelmingly likely to be ephemeral — a CI
// runner, a one-shot job, a build helper. Observed in the field: 49 GitLab
// runner containers accumulated in one week on a single build server. A
// compose project is a declared, intentional thing and is always kept, ports
// or not. An explicit znas.service.port label is the deliberate override for
// anything this rule would otherwise drop.
func EligibleForService(c DockerContainer) bool {
	return c.Project != "" ||
		len(PublishedPorts(c.Ports)) > 0 ||
		LabelPort(c.Labels) > 0
}

// GroupServices collapses a container list into applications: one entry per
// compose project — represented by the container most likely to serve its web
// UI — plus one per standalone container. A web+db+redis stack therefore
// appears once, not three times.
//
// Election is deterministic (rank, then lowest port, then container name) so
// repeated scans elect the same container and the UI does not flicker.
//
// `known` reports whether a container is ALREADY a stored service, and admits
// it regardless of EligibleForService. This exists because docker reports no
// ports at all once a container exits: judged on its current state alone, a
// standalone service the user merely STOPPED is indistinguishable from
// ephemeral junk, and would silently vanish from the list instead of staying
// listed and startable. History speaks where the present cannot. Pass nil when
// no history is available.
func GroupServices(cs []DockerContainer, known func(DockerContainer) bool) []DiscoveredService {
	var out []DiscoveredService
	projects := map[string][]DockerContainer{}
	var projectOrder []string

	for _, c := range cs {
		if !EligibleForService(c) && (known == nil || !known(c)) {
			continue
		}
		if c.Project == "" {
			out = append(out, DiscoveredService{
				Container:   c.Name,
				ContainerID: c.ID,
				Image:       c.Image,
				State:       c.State,
				Port:        PickWebPort(c.Ports, c.Labels),
				AllPorts:    PublishedPorts(c.Ports),
			})
			continue
		}
		if _, ok := projects[c.Project]; !ok {
			projectOrder = append(projectOrder, c.Project)
		}
		projects[c.Project] = append(projects[c.Project], c)
	}

	// webRank scores how likely a container is to be the stack's front end.
	webRank := func(port int) int {
		switch {
		case knownWebPorts[port]:
			return 2
		case port > 0:
			return 1
		default:
			return 0
		}
	}

	for _, name := range projectOrder {
		items := projects[name]
		best, bestPort, bestRank := items[0], PickWebPort(items[0].Ports, items[0].Labels), -1
		bestRank = webRank(bestPort)
		for _, c := range items[1:] {
			p := PickWebPort(c.Ports, c.Labels)
			r := webRank(p)
			better := r > bestRank ||
				(r == bestRank && r > 0 && p < bestPort) ||
				(r == bestRank && (r == 0 || p == bestPort) && c.Name < best.Name)
			if better {
				best, bestPort, bestRank = c, p, r
			}
		}
		allPorts := map[int]bool{}
		var flat []int
		for _, c := range items {
			for _, p := range PublishedPorts(c.Ports) {
				if !allPorts[p] {
					allPorts[p] = true
					flat = append(flat, p)
				}
			}
		}
		sort.Ints(flat)
		out = append(out, DiscoveredService{
			Project:     name,
			Container:   best.Name,
			ContainerID: best.ID,
			Image:       best.Image,
			State:       best.State,
			Port:        bestPort,
			AllPorts:    flat,
		})
	}
	return out
}


// ── Address selection ────────────────────────────────────────────────────────
//
// An instance running Docker is almost always multi-homed: its real NIC(s) plus
// docker0 and one bridge per compose network. Two things go wrong if we just
// take "the" address:
//
//  1. Docker's bridges (172.16/12) live INSIDE the guest — the host cannot route
//     to them, so a service pointed there can never load.
//  2. A guest with two real NICs (a LAN address and a second VLAN) yields an
//     arbitrary choice, and only one may be routable from this host. Observed in
//     the field: the same instance reported 192.168.2.44 on one pass and
//     10.128.8.44 on the next.
//
// So we filter the obviously-wrong candidates and then VERIFY the rest by
// dialling the service's own port, storing only an address that actually
// answers.

// dockerBridgeAddrRe matches the addresses Docker assigns to its own bridges.
// Docker allocates from 172.17-172.31.x and always takes the .1 host address.
var dockerBridgeAddrRe = regexp.MustCompile(`^172\.(1[7-9]|2[0-9]|3[0-1])\.\d+\.1$`)

// FilterCandidateAddrs drops loopback and in-guest Docker bridge addresses,
// preserving the order of what remains.
func FilterCandidateAddrs(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if dockerBridgeAddrRe.MatchString(a) {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// addrProbeTimeout bounds each candidate dial. Discovery probes a handful of
// addresses per service, so this must stay small enough that a sweep across a
// dozen services with unreachable NICs does not stall.
const addrProbeTimeout = 700 * time.Millisecond

// PickReachableAddr returns the first candidate whose ip:port accepts a TCP
// connection. ok=false means no candidate answered — the caller should record
// the service as unreachable rather than publish a URL that cannot work.
func PickReachableAddr(candidates []string, port int) (string, bool) {
	if port < 1 || port > 65535 {
		return "", false
	}
	for _, ip := range FilterCandidateAddrs(candidates) {
		conn, err := net.DialTimeout("tcp",
			net.JoinHostPort(ip, strconv.Itoa(port)), addrProbeTimeout)
		if err == nil {
			conn.Close()
			return ip, true
		}
	}
	return "", false
}
