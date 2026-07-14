package system

import (
	"strings"
	"testing"

	"zfsnas/internal/config"
)

func TestPickMergerFSAsset(t *testing.T) {
	assets := []ghAsset{
		{Name: "mergerfs_2.40.2.debian-bullseye_amd64.deb", URL: "u1"},
		{Name: "mergerfs_2.40.2.debian-bookworm_amd64.deb", URL: "u2"},
		{Name: "mergerfs_2.40.2.ubuntu-noble_amd64.deb", URL: "u3"},
		{Name: "mergerfs_2.40.2.debian-bookworm_arm64.deb", URL: "u4"},
		{Name: "mergerfs-static-linux_amd64.tar.gz", URL: "us"},
	}
	// Exact deb match.
	if u, deb, _ := pickMergerFSAsset(assets, "debian", "bookworm", "amd64"); u != "u2" || !deb {
		t.Errorf("bookworm/amd64 → %q deb=%v, want u2/true", u, deb)
	}
	if u, deb, _ := pickMergerFSAsset(assets, "ubuntu", "noble", "amd64"); u != "u3" || !deb {
		t.Errorf("noble → %q, want u3", u)
	}
	if u, deb, _ := pickMergerFSAsset(assets, "debian", "bookworm", "arm64"); u != "u4" || !deb {
		t.Errorf("bookworm/arm64 → %q, want u4", u)
	}
	// No deb for this codename (e.g. Debian trixie) → static fallback.
	if u, deb, _ := pickMergerFSAsset(assets, "debian", "trixie", "amd64"); u != "us" || deb {
		t.Errorf("trixie → %q deb=%v, want static us/false", u, deb)
	}
	// Nothing for this arch at all.
	if u, _, _ := pickMergerFSAsset(assets, "debian", "trixie", "riscv64"); u != "" {
		t.Errorf("riscv64 → %q, want empty", u)
	}
}

func TestMergerfsPathAllowed(t *testing.T) {
	mounts := []string{"/tank", "/tank/media", "/bigraid"}
	ok := []string{"/mnt", "/mnt/pool", "/mnt/a/b", "/tank", "/tank/media/x", "/bigraid/y"}
	bad := []string{"relative/path", "/etc/passwd", "/home/user", "/", "/tankfoo"}
	for _, p := range ok {
		if !mergerfsPathAllowed(p, mounts) {
			t.Errorf("expected allowed: %q", p)
		}
	}
	for _, p := range bad {
		if mergerfsPathAllowed(p, mounts) {
			t.Errorf("expected rejected: %q", p)
		}
	}
}

func TestResolveBranchDataset(t *testing.T) {
	ds := map[string]string{
		"tank":         "/tank",
		"tank/media":   "/tank/media",
		"tank/media/tv": "/tank/media/tv",
		"bigraid/data": "/bigraid/data",
	}
	// Deepest prefix wins.
	if got := resolveBranchDataset("/tank/media/tv/show", ds); got != "tank/media/tv" {
		t.Errorf("got %q, want tank/media/tv", got)
	}
	if got := resolveBranchDataset("/tank/media", ds); got != "tank/media" {
		t.Errorf("got %q, want tank/media", got)
	}
	if got := resolveBranchDataset("/tank/other", ds); got != "tank" {
		t.Errorf("got %q, want tank", got)
	}
	// Not under any dataset → non-ZFS branch.
	if got := resolveBranchDataset("/mnt/usbdisk", ds); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestMergerfsOptsString(t *testing.T) {
	p := config.MergerFSPool{
		Name: "media", CreatePolicy: "epmfs", MinFreeSpace: "100G",
		MoveOnENOSPC: true, CacheFiles: "off", DropCacheOnClose: true,
		AllowOther: true, InodeCalc: "path-hash",
	}
	got := mergerfsOptsString(p)
	for _, want := range []string{
		"category.create=epmfs", "minfreespace=100G", "moveonenospc=true",
		"cache.files=off", "dropcacheonclose=true", "inodecalc=path-hash",
		"fsname=media", "allow_other",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("opts %q missing %q", got, want)
		}
	}
	// Defaults when unset; allow_other omitted when false.
	d := mergerfsOptsString(config.MergerFSPool{Name: "x"})
	if !strings.Contains(d, "category.create=mfs") || !strings.Contains(d, "minfreespace=50G") {
		t.Errorf("defaults missing in %q", d)
	}
	if strings.Contains(d, "allow_other") {
		t.Errorf("allow_other should be absent when false: %q", d)
	}
}

func TestMergerfsUnitContent(t *testing.T) {
	p := config.MergerFSPool{
		Name: "media", Mountpoint: "/mnt/media",
		Branches: []config.MergerFSBranch{{Path: "/tank/media"}, {Path: "/bigraid/media"}},
		CreatePolicy: "mfs", AllowOther: true,
	}
	u := mergerfsUnitContent(p)
	for _, want := range []string{
		"Type=fuse.mergerfs",
		"What=/tank/media:/bigraid/media",
		"Where=/mnt/media",
		"After=zfs-import.target zfs-mount.service zfs.target",
		"nofail",
		"timeout 30",
		"mountpoint -q",
		"/tank/media",
		"/bigraid/media",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
}
