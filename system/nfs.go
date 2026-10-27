package system

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	exportsPath    = "/etc/exports"
	nfsBeginMarker = "# ===== ZFS NAS MANAGED EXPORTS BEGIN ====="
	nfsEndMarker   = "# ===== ZFS NAS MANAGED EXPORTS END ====="
)

// NFSShare represents a single /etc/exports entry.
// NFSClientRule is one client of an export with its own access level.
type NFSClientRule struct {
	Host     string `json:"host"` // "*", IP, CIDR, host name, *.domain, @netgroup
	ReadOnly bool   `json:"read_only"`
}

type NFSShare struct {
	ID             string `json:"id"`
	Path           string `json:"path"`
	Client         string `json:"client"` // space-separated hosts (kept in sync with Clients)
	ReadOnly       bool   `json:"read_only"`
	Sync           bool   `json:"sync"`
	NoSubtreeCheck bool   `json:"no_subtree_check"`
	NoRootSquash   bool   `json:"no_root_squash"` // kept in sync with Squash == "none"
	Comment        string `json:"comment"`
	// v6.10.20 — per-client access and the export options Kubernetes / CSI,
	// macOS and nested ZFS datasets need. All optional: older shares load
	// unchanged (Normalize derives the new fields from the old ones).
	Clients  []NFSClientRule `json:"clients,omitempty"`
	Squash   string          `json:"squash,omitempty"`  // "root" (default) | "none" | "all"
	AnonUID  *int            `json:"anonuid,omitempty"` // squashed users map to this uid
	AnonGID  *int            `json:"anongid,omitempty"`
	Insecure bool            `json:"insecure,omitempty"` // allow client ports above 1024 (macOS, some containers)
	CrossMnt bool            `json:"crossmnt,omitempty"` // also export the ZFS datasets mounted below the path
	// Disabled = true omits the share from /etc/exports so it is not accessible,
	// without deleting its configuration.
	Disabled bool `json:"disabled,omitempty"`
}

func nfsSharesPath(configDir string) string {
	return filepath.Join(configDir, "nfs-shares.json")
}

// ListNFSShares returns all configured NFS shares from the JSON store.
func ListNFSShares(configDir string) ([]NFSShare, error) {
	data, err := os.ReadFile(nfsSharesPath(configDir))
	if os.IsNotExist(err) {
		return []NFSShare{}, nil
	}
	if err != nil {
		return nil, err
	}
	var shares []NFSShare
	if err := json.Unmarshal(data, &shares); err != nil {
		return nil, err
	}
	if shares == nil {
		return []NFSShare{}, nil
	}
	return shares, nil
}

// SaveNFSShares persists shares to JSON and writes /etc/exports.
func SaveNFSShares(configDir string, shares []NFSShare) error {
	data, err := json.MarshalIndent(shares, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(nfsSharesPath(configDir), data, 0640); err != nil {
		return err
	}
	return applyExports(shares)
}

func applyExports(shares []NFSShare) error {
	var sb strings.Builder
	sb.WriteString(nfsBeginMarker + "\n")
	for _, s := range shares {
		if s.Disabled {
			continue // omit from /etc/exports; keeps config but makes share inaccessible
		}
		if s.Comment != "" {
			sb.WriteString("# " + s.Comment + "\n")
		}
		s.Normalize()
		var parts []string
		for _, c := range s.Clients {
			parts = append(parts, fmt.Sprintf("%s(%s)", c.Host, nfsOpts(s, c)))
		}
		sb.WriteString(fmt.Sprintf("%s %s\n", s.Path, strings.Join(parts, " ")))
	}
	sb.WriteString(nfsEndMarker + "\n")
	managed := sb.String()

	existing, err := os.ReadFile(exportsPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read /etc/exports: %w", err)
	}
	conf := string(existing)

	begin := strings.Index(conf, nfsBeginMarker)
	end := strings.Index(conf, nfsEndMarker)
	var newConf string
	if begin >= 0 && end > begin {
		newConf = conf[:begin] + managed + conf[end+len(nfsEndMarker):]
		newConf = strings.ReplaceAll(newConf, "\n\n\n", "\n\n")
	} else {
		newConf = strings.TrimRight(conf, "\n") + "\n\n" + managed
	}

	if err := writeFileSudo(exportsPath, newConf); err != nil {
		return err
	}
	return ExportFS()
}

// Normalize fills the v6.10.20 fields from the older ones (and back), so a
// share saved by any version exports the same way.
func (s *NFSShare) Normalize() {
	switch s.Squash {
	case "root", "none", "all":
	default:
		if s.NoRootSquash {
			s.Squash = "none"
		} else {
			s.Squash = "root"
		}
	}
	s.NoRootSquash = s.Squash == "none"
	if len(s.Clients) == 0 {
		hosts := strings.Fields(s.Client)
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		for _, h := range hosts {
			s.Clients = append(s.Clients, NFSClientRule{Host: h, ReadOnly: s.ReadOnly})
		}
	}
	hosts := make([]string, 0, len(s.Clients))
	allRO := true
	for i := range s.Clients {
		s.Clients[i].Host = strings.TrimSpace(s.Clients[i].Host)
		hosts = append(hosts, s.Clients[i].Host)
		allRO = allRO && s.Clients[i].ReadOnly
	}
	s.Client = strings.Join(hosts, " ")
	s.ReadOnly = allRO
}

// nfsHostRe accepts what exports(5) calls a client: "*", an IP or CIDR, a
// host name or wildcard (*.lan, node?), or an @netgroup. No spaces, commas or
// parentheses, which would inject options into /etc/exports.
var nfsHostRe = regexp.MustCompile(`^(\*|@[A-Za-z0-9._-]+|[A-Za-z0-9*?._:\[\]-]+(/[0-9]{1,3})?)$`)

// ValidateNFSShare checks a normalized share before it is written.
func ValidateNFSShare(s NFSShare) error {
	if !strings.HasPrefix(s.Path, "/") || strings.ContainsAny(s.Path, " \t\n\"") {
		return fmt.Errorf("the path must be an absolute path without spaces")
	}
	if len(s.Clients) == 0 {
		return fmt.Errorf("at least one client is required")
	}
	seen := map[string]bool{}
	for _, c := range s.Clients {
		if !nfsHostRe.MatchString(c.Host) {
			return fmt.Errorf("invalid client %q: use *, an IP address, a subnet (10.0.0.0/24), a host name or @netgroup", c.Host)
		}
		if seen[c.Host] {
			return fmt.Errorf("client %q is listed twice", c.Host)
		}
		seen[c.Host] = true
	}
	for name, v := range map[string]*int{"anonuid": s.AnonUID, "anongid": s.AnonGID} {
		if v != nil && (*v < 0 || *v > 4294967294) {
			return fmt.Errorf("%s must be between 0 and 4294967294", name)
		}
	}
	return nil
}

// NFSShareOpenToEveryone reports a share that lets any host act as root:
// no root squash on a "*" client (the UI warns about it).
func NFSShareOpenToEveryone(s NFSShare) bool {
	if s.Squash != "none" {
		return false
	}
	for _, c := range s.Clients {
		if c.Host == "*" {
			return true
		}
	}
	return false
}

func nfsOpts(s NFSShare, c NFSClientRule) string {
	opts := []string{}
	if c.ReadOnly {
		opts = append(opts, "ro")
	} else {
		opts = append(opts, "rw")
	}
	if s.Sync {
		opts = append(opts, "sync")
	} else {
		opts = append(opts, "async")
	}
	if s.NoSubtreeCheck {
		opts = append(opts, "no_subtree_check")
	}
	switch s.Squash {
	case "none":
		opts = append(opts, "no_root_squash")
	case "all":
		opts = append(opts, "all_squash")
	}
	if s.AnonUID != nil {
		opts = append(opts, fmt.Sprintf("anonuid=%d", *s.AnonUID))
	}
	if s.AnonGID != nil {
		opts = append(opts, fmt.Sprintf("anongid=%d", *s.AnonGID))
	}
	if s.Insecure {
		opts = append(opts, "insecure")
	}
	if s.CrossMnt {
		opts = append(opts, "crossmnt")
	}
	return strings.Join(opts, ",")
}

// ExportFS applies the current /etc/exports to the running kernel.
func ExportFS() error {
	out, err := exec.Command("sudo", "exportfs", "-ra").CombinedOutput()
	if err != nil {
		return fmt.Errorf("exportfs -ra: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// IsNFSInstalled checks whether the exportfs binary is present.
func IsNFSInstalled() bool {
	return binaryInstalled("exportfs")
}

// NFSStatus returns "active", "inactive", or "not-installed".
func NFSStatus() string {
	if !IsNFSInstalled() {
		return "not-installed"
	}
	out, err := exec.Command("systemctl", "is-active", "nfs-server").Output()
	if err != nil {
		return "inactive"
	}
	return strings.TrimSpace(string(out))
}

// GetNFSSessions returns active NFS mounts grouped by export path.
//
// Three sources are tried in order; results are deduplicated:
//  1. "ss -tnH sport = :2049" — lists all established TCP connections to the
//     NFS port (works for both NFSv3 and NFSv4, no sudo required).
//  2. "showmount -a --no-headers" — covers NFSv3 setups where showmount is
//     installed; gives exact client:path pairs.
//  3. /proc/fs/nfsd/clients/ — NFSv4 kernel client table (read without sudo
//     on kernels that allow it).
//
// For sources 1 and 3 the client IP is matched against the configured exports
// by CIDR/wildcard to produce a per-export breakdown.
func GetNFSSessions(exports []NFSShare) map[string][]ShareClient {
	result := make(map[string][]ShareClient)
	seen := make(map[string]map[string]bool)

	addClient := func(path, ip string) {
		// Normalise IPv4-mapped IPv6 (e.g. "::ffff:192.168.1.1" → "192.168.1.1").
		ip = strings.TrimPrefix(ip, "::ffff:")
		if seen[path] == nil {
			seen[path] = make(map[string]bool)
		}
		if seen[path][ip] {
			return
		}
		seen[path][ip] = true
		result[path] = append(result[path], ShareClient{
			IP:   ip,
			FQDN: reverseLookup(ip),
		})
	}

	// Source 1: ss (no sudo, works for NFSv3 + NFSv4).
	// Output format: "ESTAB 0 0 server:2049 client:port"
	if out, err := exec.Command("ss", "-tnH", "sport = :2049").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			// fields[4] is the peer address "ip:port" or "[ipv6]:port"
			ip, _, err := net.SplitHostPort(fields[4])
			if err != nil {
				continue
			}
			for _, exp := range exports {
				if nfsClientMatches(ip, exp.Client) {
					addClient(exp.Path, ip)
				}
			}
		}
	}

	// Source 2: showmount (NFSv3, gives exact client:path pairs).
	if out, err := exec.Command("showmount", "-a", "--no-headers").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			idx := strings.LastIndex(line, ":")
			if idx <= 0 {
				continue
			}
			host := strings.TrimSpace(line[:idx])
			path := strings.TrimSpace(line[idx+1:])
			if host == "" || !strings.HasPrefix(path, "/") {
				continue
			}
			addClient(path, host)
		}
	}

	// Source 3: /proc/fs/nfsd/clients/ (NFSv4, readable without sudo on some kernels).
	if entries, err := os.ReadDir("/proc/fs/nfsd/clients"); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			data, err := os.ReadFile("/proc/fs/nfsd/clients/" + e.Name() + "/info")
			if err != nil {
				continue
			}
			ip := ""
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "address:") {
					addr := strings.TrimSpace(strings.TrimPrefix(line, "address:"))
					if h, _, e2 := net.SplitHostPort(addr); e2 == nil {
						ip = h
					} else {
						ip = addr
					}
					break
				}
			}
			if ip == "" {
				continue
			}
			for _, exp := range exports {
				if nfsClientMatches(ip, exp.Client) {
					addClient(exp.Path, ip)
				}
			}
		}
	}

	return result
}

// nfsClientMatches reports whether ip is covered by the export's client field.
// client may be a space-separated list of IPs, CIDRs, or "*".
func nfsClientMatches(ip, client string) bool {
	for _, c := range strings.Fields(client) {
		if c == "*" {
			return true
		}
		if strings.Contains(c, "/") {
			_, network, err := net.ParseCIDR(c)
			if err != nil {
				continue
			}
			if parsed := net.ParseIP(ip); parsed != nil && network.Contains(parsed) {
				return true
			}
		} else if ip == c {
			return true
		}
	}
	return client == "" // empty means any
}

// ControlNFS runs systemctl start/stop/restart on nfs-server.
func ControlNFS(action string) error {
	if action != "start" && action != "stop" && action != "restart" {
		return fmt.Errorf("invalid action: %s", action)
	}
	out, err := exec.Command("sudo", "systemctl", action, "nfs-server").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s nfs-server: %s", action, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetNFSShareDisabled marks an NFS share as disabled or enabled in the JSON
// config and rewrites /etc/exports. The caller is responsible for calling
// ExportFS() after all desired share changes have been applied.
func SetNFSShareDisabled(configDir, id string, disabled bool) error {
	shares, err := ListNFSShares(configDir)
	if err != nil {
		return err
	}
	for i := range shares {
		if shares[i].ID == id {
			shares[i].Disabled = disabled
			return SaveNFSShares(configDir, shares)
		}
	}
	return fmt.Errorf("NFS share not found: %s", id)
}

// ChmodNFSPath sets permissions 0777 on the given path so that NFS clients
// have full read/write access regardless of the connecting user's UID/GID.
func ChmodNFSPath(path string) error {
	out, err := exec.Command("sudo", "chmod", "0777", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("chmod 0777 %s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}
