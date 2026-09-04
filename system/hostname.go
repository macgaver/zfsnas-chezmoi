// Host naming: read and change the system hostname from the portal.
package system

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Paths are vars so tests can point them at a temp dir.
var (
	etcHostnamePath = "/etc/hostname"
	etcHostsPath    = "/etc/hosts"
)

// hostnameRe is RFC 1123 for a single label: letters, digits and hyphens, not
// starting or ending with a hyphen. We take the short name only — a FQDN's
// domain part belongs to DNS, not to /etc/hostname, and Samba's NetBIOS name
// is derived from this, which cannot hold a dot.
var hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// GetHostname returns the running system hostname.
func GetHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// ValidateHostname checks a proposed name and returns why it is unusable.
func ValidateHostname(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("a hostname is required")
	case len(name) > 63:
		return fmt.Errorf("a hostname can be at most 63 characters")
	case strings.Contains(name, "."):
		return fmt.Errorf("use the short name only (no dots) — the domain part comes from DNS")
	case !hostnameRe.MatchString(name):
		return fmt.Errorf("a hostname may only contain letters, digits and hyphens, and cannot start or end with a hyphen")
	case strings.EqualFold(name, "localhost"):
		return fmt.Errorf("%q is reserved", name)
	}
	return nil
}

// SetHostname changes the hostname now and keeps it across reboots.
//
// Three things have to move together, or the box comes back confused:
//   - /etc/hostname, which is what the next boot reads
//   - the running kernel hostname, so the change is live
//   - the 127.0.1.1 line in /etc/hosts, so the new name still resolves —
//     without it sudo, Samba and anything else calling gethostbyname() on its
//     own name stalls or warns on every invocation
//
// The file is written in place rather than through hostnamectl on purpose:
// hostnamectl replaces /etc/hostname via rename, and on the USB appliance that
// file is a bind mount from the persist store, where a rename fails with
// EBUSY. Writing in place works in both worlds, and persists on the appliance
// precisely because of that bind.
func SetHostname(name string) error {
	if err := ValidateHostname(name); err != nil {
		return err
	}
	old := GetHostname()
	if name == old {
		return nil
	}

	if err := writeSystemFile(etcHostnamePath, []byte(name+"\n")); err != nil {
		return fmt.Errorf("write %s: %w", etcHostnamePath, err)
	}
	// Apply from the file we just wrote — `hostname -F <file>` takes no
	// user-controlled argument, so the sudoers grant needs no wildcard.
	if out, err := runMaybeSudo("/usr/bin/hostname", "-F", etcHostnamePath); err != nil {
		return fmt.Errorf("apply hostname: %s", strings.TrimSpace(string(out)))
	}
	if err := updateEtcHosts(old, name); err != nil {
		// The name is already live and persisted; a stale hosts entry is worth
		// reporting but not worth failing the change over.
		return fmt.Errorf("hostname changed to %s, but %s could not be updated: %w", name, etcHostsPath, err)
	}
	return nil
}

// updateEtcHosts rewrites the loopback line that names this host. Only an
// entry that actually carried the old name is touched — a hand-maintained
// hosts file keeps everything else exactly as it was.
func updateEtcHosts(oldName, newName string) error {
	data, err := os.ReadFile(etcHostsPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	changed := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if fields[0] != "127.0.1.1" && fields[0] != "127.0.0.1" {
			continue
		}
		for j := 1; j < len(fields); j++ {
			if fields[j] == oldName {
				fields[j] = newName
				lines[i] = strings.Join(fields, "\t")
				changed = true
				break
			}
		}
	}
	if !changed {
		// No line claimed the old name (fresh install, or the admin removed
		// it). Give the new name one so it resolves.
		body := strings.TrimRight(string(data), "\n")
		return writeSystemFile(etcHostsPath, []byte(body+"\n127.0.1.1\t"+newName+"\n"))
	}
	return writeSystemFile(etcHostsPath, []byte(strings.Join(lines, "\n")))
}

// writeSystemFile writes a root-owned file in place, via sudo tee when the
// portal is not running as root. In place matters: several of these paths are
// bind mounts on the appliance, where a replace-by-rename fails with EBUSY.
func writeSystemFile(path string, data []byte) error {
	if os.Getuid() == 0 {
		return os.WriteFile(path, data, 0644)
	}
	cmd := exec.Command("sudo", "-n", "/usr/bin/tee", path)
	cmd.Stdin = strings.NewReader(string(data))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// runMaybeSudo runs a privileged command directly as root, or through sudo.
func runMaybeSudo(bin string, args ...string) ([]byte, error) {
	if os.Getuid() == 0 {
		return exec.Command(bin, args...).CombinedOutput()
	}
	return exec.Command("sudo", append([]string{"-n", bin}, args...)...).CombinedOutput()
}
