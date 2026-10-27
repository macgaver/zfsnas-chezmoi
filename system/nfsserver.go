package system

// nfsserver.go — server-wide NFS settings (v6.10.20).
//
// ZNAS writes them to its own drop-in, /etc/nfs.conf.d/zfsnas.conf, which
// nfs-utils (2.8 on Debian 13 / Ubuntu 26.04) reads after /etc/nfs.conf; the
// distro file is never edited. The drop-in is re-applied at every portal
// start: on the USB appliance /etc lives in RAM, so a hand edit of nfs.conf
// (e.g. manage-gids for Kubernetes) was lost at every reboot.

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"zfsnas/internal/config"
)

const nfsDropIn = "/etc/nfs.conf.d/zfsnas.conf"

// BuildNFSDropIn renders the drop-in; "" when every setting is at its default.
func BuildNFSDropIn(c config.NFSServerConfig) string {
	var mountd, nfsd []string
	if c.TrustClientGroups {
		mountd = append(mountd, "manage-gids = n")
	}
	if c.Threads > 0 {
		nfsd = append(nfsd, fmt.Sprintf("threads = %d", c.Threads))
	}
	if c.DisableV3 {
		nfsd = append(nfsd, "vers3 = n")
	}
	if len(mountd) == 0 && len(nfsd) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# Managed by ZNAS (Sharing → NFS → Server settings). Do not edit:\n")
	b.WriteString("# this file is rewritten at every portal start.\n")
	if len(mountd) > 0 {
		b.WriteString("\n[mountd]\n" + strings.Join(mountd, "\n") + "\n")
	}
	if len(nfsd) > 0 {
		b.WriteString("\n[nfsd]\n" + strings.Join(nfsd, "\n") + "\n")
	}
	return b.String()
}

// nfsDropInEmpty is written instead of deleting the drop-in once every
// setting is back to its default: on the USB appliance the file is a bind
// mount from the persist store, which cannot be removed.
const nfsDropInEmpty = "# Managed by ZNAS (Sharing → NFS → Server settings): no settings, distro defaults apply.\n"

// ApplyNFSServerSettings brings the drop-in in line with c and restarts the
// NFS server when it changed (and the server is running or starting).
// Returns whether a change was made.
func ApplyNFSServerSettings(c config.NFSServerConfig) (bool, error) {
	if c.DisableV3 {
		if mi, err := os.ReadFile("/proc/self/mountinfo"); err == nil && rootOverlayNotExportable(string(mi)) {
			c.DisableV3 = false // NFSv4 cannot work here: keep v3 or every client is cut off
		}
	}
	want := BuildNFSDropIn(c)
	cur, err := os.ReadFile(nfsDropIn)
	if err != nil && want == "" {
		return false, nil // nothing there, nothing wanted
	}
	if want == "" {
		want = nfsDropInEmpty
	}
	if err == nil && string(cur) == want {
		return false, nil
	}
	if out, err := exec.Command("sudo", "mkdir", "-p", "/etc/nfs.conf.d").CombinedOutput(); err != nil {
		return false, fmt.Errorf("create /etc/nfs.conf.d: %s", strings.TrimSpace(string(out)))
	}
	tee := exec.Command("sudo", "/usr/bin/tee", nfsDropIn)
	tee.Stdin = strings.NewReader(want)
	if out, err := tee.CombinedOutput(); err != nil {
		return false, fmt.Errorf("write %s: %s", nfsDropIn, strings.TrimSpace(string(out)))
	}
	// mountd, nfsd and friends are PartOf nfs-server: one restart picks the
	// new settings up everywhere. Not started when NFS is off. At boot the
	// portal can race nfs-server, still "activating" while rpc.mountd has
	// already read the old configuration — restart then too.
	if out, _ := exec.Command("systemctl", "is-active", "nfs-server", "nfs-mountd").Output(); nfsUnitsRunning(string(out)) {
		if out, err := exec.Command("sudo", "systemctl", "restart", "nfs-server").CombinedOutput(); err != nil {
			return true, fmt.Errorf("restart nfs-server: %s", strings.TrimSpace(string(out)))
		}
	}
	return true, nil
}

// nfsUnitsRunning reads `systemctl is-active` output (one state per unit).
func nfsUnitsRunning(out string) bool {
	for _, st := range strings.Fields(out) {
		if st == "active" || st == "activating" || st == "reloading" {
			return true
		}
	}
	return false
}

// NFSEffective is what the NFS server actually uses (all config files merged).
type NFSEffective struct {
	ManageGids bool   `json:"manage_gids"`
	Threads    string `json:"threads"`
	V3         bool   `json:"v3"`
	Available  bool   `json:"available"` // nfsconf present
	// V4RootBroken: "/" is an overlay mounted without nfs_export (USB
	// appliance images before 26.04.1-6), so the NFSv4 pseudo-root cannot
	// be exported and clients only get NFSv3.
	V4RootBroken bool `json:"v4_root_broken"`
}

// rootOverlayNotExportable parses /proc/self/mountinfo for the "/" mount.
func rootOverlayNotExportable(mountinfo string) bool {
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[4] != "/" {
			continue
		}
		// fields after " - ": fstype, source, super options
		for i, v := range f {
			if v == "-" && i+3 < len(f) {
				if f[i+1] != "overlay" {
					return false
				}
				return !strings.Contains(","+f[i+3]+",", ",nfs_export=on,")
			}
		}
	}
	return false
}

func nfsconfGet(section, key string) (string, bool) {
	out, err := exec.Command("nfsconf", "--get", section, key).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func nfsYes(v string) bool {
	switch strings.ToLower(v) {
	case "y", "yes", "1", "true", "on":
		return true
	}
	return false
}

// GetNFSEffective reads the merged configuration through nfsconf.
func GetNFSEffective() NFSEffective {
	e := NFSEffective{V3: true}
	if mi, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		e.V4RootBroken = rootOverlayNotExportable(string(mi))
	}
	if _, err := exec.LookPath("nfsconf"); err != nil {
		return e
	}
	e.Available = true
	if v, ok := nfsconfGet("mountd", "manage-gids"); ok {
		e.ManageGids = nfsYes(v)
	}
	if v, ok := nfsconfGet("nfsd", "threads"); ok {
		e.Threads = v
	}
	if v, ok := nfsconfGet("nfsd", "vers3"); ok {
		e.V3 = nfsYes(v)
	}
	return e
}
