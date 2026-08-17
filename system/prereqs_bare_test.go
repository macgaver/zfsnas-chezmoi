package system

import "testing"

// A sudoers entry with NO argument spec permits ANY arguments, so it satisfies
// every argument-bearing check. sudo-rs hosts get exactly this shape, because
// sudo-rs cannot match '*' inside arguments (see sudoers_hardening.go).
//
// Before this, the Requisites page reported "zpool *", "zfs *", "smartctl *" …
// as missing on every sudo-rs host whose grant was strictly WIDER than required.
// Sample below is the real `sudo -l -n` output shape from znas3 (sudo-rs 0.2.13).
func TestSudoListGrantsBare(t *testing.T) {
	rsList := `User zfsnas may run the following commands on znas3:
    (ALL) NOPASSWD: /usr/sbin/zpool, /usr/sbin/zfs, /usr/bin/systemctl reload smbd,
    /usr/sbin/smartctl, /usr/bin/tee /etc/samba/smb.conf, /usr/bin/cat`

	for _, tc := range []struct {
		path, binary string
		want         bool
	}{
		{"/usr/sbin/zpool", "zpool", true},
		{"/usr/sbin/zfs", "zfs", true},
		{"/usr/sbin/smartctl", "smartctl", true},
		{"/usr/bin/cat", "cat", true},
		// Only granted WITH an argument — not a bare grant.
		{"/usr/bin/tee", "tee", false},
		// Never granted at all.
		{"/usr/bin/passwd", "passwd", false},
	} {
		if got := sudoListGrantsBare(rsList, tc.path, tc.binary); got != tc.want {
			t.Errorf("sudoListGrantsBare(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// A classic host lists argument-constrained entries; a bare grant must NOT be
// inferred from them, or the check would pass on a host that cannot run the
// command with the arguments the portal needs.
func TestSudoListGrantsBareRejectsArgConstrained(t *testing.T) {
	classic := `User zfsnas may run the following commands on znas5:
    (ALL) NOPASSWD: /usr/sbin/zpool *, /usr/bin/dd if=/dev/zero *, /usr/bin/tee /etc/exports`
	for _, tc := range []struct{ path, binary string }{
		{"/usr/sbin/zpool", "zpool"},
		{"/usr/bin/dd", "dd"},
		{"/usr/bin/tee", "tee"},
	} {
		if sudoListGrantsBare(classic, tc.path, tc.binary) {
			t.Errorf("%s: argument-constrained entry misread as a bare grant", tc.path)
		}
	}
}
