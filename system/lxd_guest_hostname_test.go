package system

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuestHostnameSyncArgsPassesNameAsArgument(t *testing.T) {
	args, err := guestHostnameSyncArgs("home-assistant")
	if err != nil {
		t.Fatal(err)
	}
	if args[len(args)-1] != "home-assistant" || args[len(args)-2] != "sh" {
		t.Fatalf("name must be the script's $1, got argv tail %q", args[len(args)-2:])
	}
	if strings.Contains(guestHostnameSyncScript, "home-assistant") {
		t.Fatal("the instance name must never be interpolated into the script")
	}
	for _, bad := range []string{"", "a;reboot", "$(id)", "x y", "-x", "a.b"} {
		if _, err := guestHostnameSyncArgs(bad); err == nil {
			t.Errorf("guestHostnameSyncArgs(%q) accepted an invalid name", bad)
		}
	}
}

// runGuestSync runs the real script with stubbed guest commands.
// cur = what `hostname` reports; networkd = whether systemd-networkd is active.
func runGuestSync(t *testing.T, want, cur string, networkd bool, hosts string) (out, hostsAfter, calls string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	log := filepath.Join(dir, "calls")
	stub := func(name, body string) {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \""+name+" $*\" >> "+log+"\n"+body+"\n"), 0o755)
	}
	stub("hostname", "echo "+cur)
	stub("hostnamectl", "exit 0")
	stub("ip", "echo 'default via 192.168.2.1 dev enp5s0 proto dhcp'")
	if networkd {
		stub("systemctl", "exit 0")
	} else {
		stub("systemctl", "exit 3")
	}
	stub("networkctl", "exit 0")
	hostsFile := filepath.Join(dir, "hosts")
	os.WriteFile(hostsFile, []byte(hosts), 0o644)

	cmd := exec.Command("sh", "-c", guestHostnameSyncScript, "sh", want)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "ZNAS_HOSTS_FILE="+hostsFile)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	h, _ := os.ReadFile(hostsFile)
	c, _ := os.ReadFile(log)
	return strings.TrimSpace(string(b)), string(h), string(c)
}

func TestGuestHostnameSyncRenewsLeaseWhenNameAlreadyRight(t *testing.T) {
	// The case seen in the field: Incus fixed /etc/hostname, but the lease
	// was taken under the image's placeholder name.
	hosts := "127.0.1.1\thome-assistant\n127.0.0.1\tlocalhost\n"
	out, after, calls := runGuestSync(t, "home-assistant", "home-assistant", true, hosts)
	if !strings.Contains(calls, "networkctl renew enp5s0") {
		t.Fatalf("lease not renewed on the default-route device; calls:\n%s", calls)
	}
	if strings.Contains(calls, "hostnamectl") || after != hosts {
		t.Fatalf("hostname was already right — nothing should change; calls:\n%s\nhosts:\n%s", calls, after)
	}
	if !strings.Contains(out, "renewed as home-assistant") {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestGuestHostnameSyncFixesPlaceholderName(t *testing.T) {
	hosts := "127.0.0.1\tlocalhost\n127.0.1.1\tdistrobuilder-03a4af62\n::1\tlocalhost\n"
	_, after, calls := runGuestSync(t, "home-assistant", "distrobuilder-03a4af62", true, hosts)
	if !strings.Contains(calls, "hostnamectl set-hostname home-assistant") {
		t.Fatalf("hostname not set; calls:\n%s", calls)
	}
	want := "127.0.0.1\tlocalhost\n127.0.1.1\thome-assistant\n::1\tlocalhost\n"
	if after != want {
		t.Fatalf("/etc/hosts =\n%q\nwant\n%q", after, want)
	}
	if !strings.Contains(calls, "networkctl renew enp5s0") {
		t.Fatalf("lease not renewed; calls:\n%s", calls)
	}
}

func TestGuestHostnameSyncAddsHostsEntryWhenMissing(t *testing.T) {
	_, after, _ := runGuestSync(t, "plex", "localhost", true, "127.0.0.1\tlocalhost\n")
	if after != "127.0.0.1\tlocalhost\n127.0.1.1\tplex\n" {
		t.Fatalf("/etc/hosts = %q", after)
	}
}

func TestGuestHostnameSyncNeverRenamesAChosenHostname(t *testing.T) {
	// Existing VMs reach this on their next start: instance "nc" whose guest
	// was deliberately named "nextcloud" must keep that name.
	hosts := "127.0.1.1\tnextcloud\n"
	_, after, calls := runGuestSync(t, "nc", "nextcloud", true, hosts)
	if strings.Contains(calls, "hostnamectl") || after != hosts {
		t.Fatalf("a non-placeholder hostname was changed; calls:\n%s\nhosts:\n%s", calls, after)
	}
	if !strings.Contains(calls, "networkctl renew enp5s0") {
		t.Fatalf("lease should still be renewed; calls:\n%s", calls)
	}
}

func TestLXDSyncVMHostnameAfterBootIgnoresInvalidNames(t *testing.T) {
	// Must return before touching incus (none exists in the test environment).
	for _, n := range []string{"", "a;b", "x.y"} {
		LXDSyncVMHostnameAfterBoot(n)
	}
}

func TestGuestHostnameSyncLeavesOtherNetworkStacksAlone(t *testing.T) {
	out, _, calls := runGuestSync(t, "vm1", "vm1", false, "127.0.1.1\tvm1\n")
	if strings.Contains(calls, "networkctl") {
		t.Fatalf("networkctl must not run without systemd-networkd; calls:\n%s", calls)
	}
	if !strings.Contains(out, "not using systemd-networkd") {
		t.Fatalf("unexpected output %q", out)
	}
}
