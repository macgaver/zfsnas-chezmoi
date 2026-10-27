package system

import (
	"strings"
	"testing"

	"zfsnas/internal/config"
)

func TestNFSNormalizeLegacyShare(t *testing.T) {
	s := NFSShare{Path: "/mnt/tank/k8s", Client: "10.0.0.1 10.0.0.2", ReadOnly: false, NoRootSquash: true}
	s.Normalize()
	if s.Squash != "none" || len(s.Clients) != 2 || s.Clients[1].Host != "10.0.0.2" || s.Clients[0].ReadOnly {
		t.Fatalf("legacy share not carried over: %+v", s)
	}
	s = NFSShare{Path: "/x"}
	s.Normalize()
	if s.Squash != "root" || len(s.Clients) != 1 || s.Clients[0].Host != "*" || s.Client != "*" {
		t.Fatalf("empty client must become *: %+v", s)
	}
}

func TestNFSValidate(t *testing.T) {
	ok := []string{"*", "10.128.8.0/24", "10.128.8.103", "fd00::1", "nas.lan", "*.lan", "@k8s", "node?"}
	for _, h := range ok {
		s := NFSShare{Path: "/mnt/a", Clients: []NFSClientRule{{Host: h}}}
		if err := ValidateNFSShare(s); err != nil {
			t.Errorf("%q rejected: %v", h, err)
		}
	}
	bad := []string{"*(rw,no_root_squash)", "10.0.0.1,10.0.0.2", "a b", "", "host)"}
	for _, h := range bad {
		s := NFSShare{Path: "/mnt/a", Clients: []NFSClientRule{{Host: h}}}
		if err := ValidateNFSShare(s); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	dup := NFSShare{Path: "/mnt/a", Clients: []NFSClientRule{{Host: "*"}, {Host: "*"}}}
	if ValidateNFSShare(dup) == nil {
		t.Error("duplicate client accepted")
	}
	neg := -1
	if ValidateNFSShare(NFSShare{Path: "/mnt/a", Clients: []NFSClientRule{{Host: "*"}}, AnonUID: &neg}) == nil {
		t.Error("negative anonuid accepted")
	}
}

func TestNFSOptions(t *testing.T) {
	uid, gid := 1000, 1000
	s := NFSShare{Path: "/mnt/k8s", Sync: true, NoSubtreeCheck: true, Squash: "all", AnonUID: &uid, AnonGID: &gid,
		Insecure: true, CrossMnt: true, Clients: []NFSClientRule{{Host: "10.0.0.0/24"}, {Host: "*", ReadOnly: true}}}
	s.Normalize()
	if got := nfsOpts(s, s.Clients[0]); got != "rw,sync,no_subtree_check,all_squash,anonuid=1000,anongid=1000,insecure,crossmnt" {
		t.Errorf("rw client: %s", got)
	}
	if got := nfsOpts(s, s.Clients[1]); !strings.HasPrefix(got, "ro,") {
		t.Errorf("ro client: %s", got)
	}
	if s.ReadOnly {
		t.Error("share with a rw client must not be marked read-only")
	}
	k := NFSShare{Path: "/mnt/k8s", Sync: true, NoSubtreeCheck: true, Squash: "none", Clients: []NFSClientRule{{Host: "*"}}}
	k.Normalize()
	if got := nfsOpts(k, k.Clients[0]); got != "rw,sync,no_subtree_check,no_root_squash" || !k.NoRootSquash {
		t.Errorf("kubernetes preset: %s", got)
	}
	if !NFSShareOpenToEveryone(k) {
		t.Error("no_root_squash on * must be flagged")
	}
}

func TestBuildNFSDropIn(t *testing.T) {
	if BuildNFSDropIn(config.NFSServerConfig{}) != "" {
		t.Error("defaults must produce no file")
	}
	got := BuildNFSDropIn(config.NFSServerConfig{TrustClientGroups: true, Threads: 16, DisableV3: true})
	for _, want := range []string{"[mountd]\nmanage-gids = n\n", "[nfsd]\nthreads = 16\nvers3 = n\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestNFSDropInSudoAllowed(t *testing.T) {
	tpl := RequiredSudoersContent()
	for _, c := range []string{"/usr/bin/tee /etc/nfs.conf.d/zfsnas.conf", "/usr/bin/rm -f /etc/nfs.conf.d/zfsnas.conf",
		"/usr/bin/mkdir -p /etc/nfs.conf.d", "/usr/bin/systemctl restart nfs-server"} {
		if !sudoersAllows(tpl, c) {
			t.Errorf("not in the hardened sudoers template: %s", c)
		}
	}
}

func TestRootOverlayNotExportable(t *testing.T) {
	casper := "28 1 0:27 / / rw,relatime shared:1 - overlay /cow rw,lowerdir=/filesystem.squashfs,upperdir=/cow/upper,workdir=/cow/work,uuid=on,xino=off,nouserxattr\n" +
		"29 28 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw\n"
	if !rootOverlayNotExportable(casper) {
		t.Error("casper overlay without nfs_export must be reported")
	}
	fixed := "28 1 0:27 / / rw,relatime shared:1 - overlay /cow rw,lowerdir=/filesystem.squashfs,upperdir=/cow/upper,workdir=/cow/work,index=on,uuid=on,nfs_export=on,nouserxattr\n"
	if rootOverlayNotExportable(fixed) {
		t.Error("overlay with nfs_export=on is exportable")
	}
	host := "26 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw,errors=remount-ro\n"
	if rootOverlayNotExportable(host) {
		t.Error("ext4 root is exportable")
	}
	// a bind of "/" elsewhere has root "/" but mount point != "/"
	other := "40 28 0:27 / /mnt/x rw - overlay o rw,lowerdir=/a\n" + host
	if rootOverlayNotExportable(other) {
		t.Error("only the / mount point counts")
	}
}

func TestNFSUnitsRunning(t *testing.T) {
	for out, want := range map[string]bool{
		"active\nactive\n": true, "activating\nactive\n": true,
		"inactive\ninactive\n": false, "failed\ninactive\n": false, "": false,
	} {
		if got := nfsUnitsRunning(out); got != want {
			t.Errorf("%q: got %v", out, got)
		}
	}
}
