// system/appliance_manifest_test.go
// Regression guard (spec 6.8.28 §4.6): every system path the portal writes
// at runtime must be covered by the USB-appliance persist manifest, or the
// setting silently vanishes on reboot. When you add a feature that writes a
// NEW absolute path, add it BOTH to usbimage/persist-manifest.txt and to
// the `required` list here.
package system

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func loadPersistManifest(t *testing.T) map[string]string { // target -> type
	t.Helper()
	f, err := os.Open("../usbimage/persist-manifest.txt")
	if err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	defer f.Close()
	entries := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fld := strings.Fields(line)
		if len(fld) != 3 {
			t.Fatalf("malformed manifest line: %q", line)
		}
		typ, target := fld[0], fld[2]
		if typ != "dir" && typ != "file" && typ != "copy" {
			t.Fatalf("bad type in line: %q", line)
		}
		if !strings.HasPrefix(target, "/") {
			t.Fatalf("target not absolute: %q", line)
		}
		if _, dup := entries[target]; dup {
			t.Fatalf("duplicate target: %q", target)
		}
		entries[target] = typ
	}
	return entries
}

// covered reports whether path is a manifest target or inside a dir target.
func covered(entries map[string]string, path string) bool {
	if _, ok := entries[path]; ok {
		return true
	}
	for target, typ := range entries {
		if typ == "dir" && strings.HasPrefix(path, target+"/") {
			return true
		}
	}
	return false
}

func TestPersistManifestCoversRuntimeWrites(t *testing.T) {
	entries := loadPersistManifest(t)
	required := []string{
		"/opt/zfsnas/config", // portal config, certs, RRD, audit
		"/etc/hostid",        // ZFS import identity
		"/etc/machine-id",    // DHCP client-ID stability
		"/etc/hostname",      // appliance identity (shell-settable, write-through)
		"/etc/hosts",         // renamed alongside the hostname; stale = sudo/Samba warnings
		"/etc/localtime",     // portal timezone setting
		"/etc/timezone",
		"/etc/passwd", "/etc/shadow", // root password from SSH-access card
		"/etc/group", "/etc/gshadow",
		"/etc/subuid", "/etc/subgid", // incus idmaps
		"/etc/ssh/sshd_config.d",     // sshd drop-ins + host keys dir
		"/root/.ssh/authorized_keys", // SSH-access card key
		// The appliance ships ifupdown, NOT netplan: netplan is purged from the
		// image and /etc/netplan is deliberately not persisted, so the portal's
		// static-IP and bridge code writes /etc/network/interfaces.
		"/etc/network/interfaces",
		"/etc/fstab",                 // mergerfs / mounts
		"/etc/zfs/zpool.cache",       // pool auto-import
		"/etc/samba/smb.conf",        // SMB shares
		"/var/lib/samba",             // SMB user passdb
		"/etc/nut",                   // UPS
		"/etc/exports",               // NFS
		"/etc/tgt",                   // iSCSI
		"/etc/minio", "/etc/default/minio",
		"/var/lib/incus", // incus DB + certs
		// dhcpcd's DUID and leases: without these the appliance presents a new
		// client identity every boot and gets a DIFFERENT address, so the
		// portal "disappears" from the URL the user bookmarked.
		"/var/lib/dhcpcd",
	}
	for _, p := range required {
		if !covered(entries, p) {
			t.Errorf("runtime-written path NOT covered by persist manifest: %s", p)
		}
	}
}
