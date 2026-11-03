package system

// Dynamic DNS (Firewall → Dynamic DNS): ddclient runs as the Firewall's own
// unit (znas-sdn-ddns.service) from a config written here; the
// distribution's ddclient.service is turned off when the Firewall installs
// the package. ddclient checks every 5 minutes and only calls the provider
// when the address changed.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

const sdnDDNSUnitName = "znas-sdn-ddns.service"

var (
	sdnDDClientConf  = "/etc/znas-sdn/ddclient.conf"
	sdnDDClientCache = "/var/cache/znas-sdn/ddclient.cache"
)

func sdnDDNSUnitPath() string { return filepath.Join(filepath.Dir(sdnUnitPath), sdnDDNSUnitName) }

func sdnDDClientBinary() string {
	for _, p := range []string{"/usr/bin/ddclient", "/usr/sbin/ddclient"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/ddclient"
}

// SDNDDClientInstalled: the ddclient package.
func SDNDDClientInstalled() bool {
	return binaryPresent("/usr/bin/ddclient") || binaryPresent("/usr/sbin/ddclient") || binaryPresent("ddclient")
}

// sdnDDNSUnitText: inert until the Firewall writes a ddclient config.
func sdnDDNSUnitText() string {
	return fmt.Sprintf(`[Unit]
Description=ZNAS Firewall — dynamic DNS (ddclient)
After=znas-sdn.service network-online.target
Wants=network-online.target
ConditionPathExists=%[1]s

[Service]
Type=simple
CacheDirectory=znas-sdn
ExecStart=%[2]s -foreground -daemon 300 -file %[1]s -cache %[3]s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
`, sdnDDClientConf, sdnDDClientBinary(), sdnDDClientCache)
}

// SDNDisableDistroDDClient: the package's own service starts on install
// with a placeholder config; the Firewall runs its own unit.
func SDNDisableDistroDDClient() {
	sdnRun.Run(nil, "systemctl", "disable", "--now", "ddclient.service") //nolint:errcheck
}

// sdnDDNSFiles writes ddclient's config (root-only: it holds the provider
// tokens), or removes it when nothing is updated. Returns whether it changed.
func sdnDDNSFiles(c *sdn.Config) (bool, error) {
	want := sdn.RenderDDClient(c)
	cur, rerr := os.ReadFile(sdnDDClientConf)
	if rerr != nil && !os.IsNotExist(rerr) {
		cur, rerr = sdnRun.Run(nil, "cat", sdnDDClientConf) // 0600 root: sudo cat
	}
	exists := rerr == nil
	switch {
	case want == "" && exists:
		return true, sdnRemoveFile(sdnDDClientConf)
	case want == "" || (exists && string(cur) == want):
		return false, nil
	}
	dir := filepath.Dir(sdnDDClientConf)
	if err := os.MkdirAll(dir, 0755); err != nil {
		sdnRun.Run(nil, "mkdir", "-p", dir) //nolint:errcheck
	}
	return true, sdnWriteSecret(sdnDDClientConf, []byte(want))
}

// sdnApplyDDNS (after the ruleset): restart on a new config, stop when gone.
func sdnApplyDDNS(changed bool, res *SDNApplyResult) {
	if _, err := os.Stat(sdnDDClientConf); err == nil || (err != nil && !os.IsNotExist(err)) {
		active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDDNSUnitName)
		if changed || strings.TrimSpace(string(active)) != "active" {
			if changed {
				// ddclient skips names whose address it already sent: a new
				// configuration (other names, a corrected token) is sent now.
				sdnRemoveFile(sdnDDClientCache) //nolint:errcheck — may not exist
			}
			if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnDDNSUnitName); err != nil {
				res.Warnings = append(res.Warnings, "dynamic DNS did not start: "+err.Error())
			}
		}
	} else if changed {
		sdnRun.Run(nil, "systemctl", "stop", sdnDDNSUnitName) //nolint:errcheck
	}
}

// SDNDDNSHost is what ddclient last did for one name.
type SDNDDNSHost struct {
	IP      string    `json:"ip,omitempty"`     // last address sent
	Status  string    `json:"status,omitempty"` // good, nochg, noconnect, badauth, nohost…
	Updated time.Time `json:"updated"`          // last successful update
	Checked time.Time `json:"checked"`          // last attempt
}

func parseDDClientCache(s string) map[string]SDNDDNSHost {
	out := map[string]SDNDDNSHost{}
	unix := func(v string) time.Time {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return time.Unix(n, 0)
		}
		return time.Time{}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv, host, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		f := map[string]string{}
		for _, p := range strings.Split(kv, ",") {
			if k, v, ok := strings.Cut(p, "="); ok {
				f[k] = v
			}
		}
		h := SDNDDNSHost{IP: f["ipv4"], Status: f["status-ipv4"], Updated: unix(f["mtime"]), Checked: unix(f["atime"])}
		if h.IP == "" {
			h.IP = f["ip"]
		}
		if h.Status == "" {
			h.Status = f["status"]
		}
		out[strings.TrimSpace(host)] = h
	}
	return out
}

// SDNDDNSStatus returns, per entry id, the state of each of its names.
func SDNDDNSStatus(c *sdn.Config) map[string]map[string]SDNDDNSHost {
	out := map[string]map[string]SDNDDNSHost{}
	if c == nil || len(c.DDNS) == 0 {
		return out
	}
	b, err := os.ReadFile(sdnDDClientCache)
	if err != nil {
		b, _ = sdnRun.Run(nil, "cat", sdnDDClientCache) // ddclient writes it 0600
	}
	cache := parseDDClientCache(string(b))
	for _, e := range c.DDNS {
		m := map[string]SDNDDNSHost{}
		suffix := sdn.DDNSProviders[e.Provider].Suffix
		for _, h := range e.Hostnames {
			if st, ok := cache[strings.TrimSuffix(h, suffix)]; ok {
				m[h] = st
			}
		}
		out[e.ID] = m
	}
	return out
}

// SDNDDNSRunning: the unit is up.
func SDNDDNSRunning() bool {
	b, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnDDNSUnitName)
	return strings.TrimSpace(string(b)) == "active"
}
