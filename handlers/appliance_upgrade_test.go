package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"zfsnas/internal/updater"
)

func TestNewestApplianceRelease(t *testing.T) {
	rels := []updater.ApplianceImageRelease{
		{Version: "26.04.1-2"}, {Version: "26.04.1-10"}, {Version: "26.04.0-3"},
	}
	if got := newestApplianceRelease(rels); got == nil || got.Version != "26.04.1-10" {
		t.Errorf("got %+v", got)
	}
	if newestApplianceRelease(nil) != nil {
		t.Error("empty list must give nil")
	}
	// A new Ubuntu point release beats any build number of the previous one,
	// and our build counter beats a legacy (build 0) image.
	if !semverGreater("26.04.2-1", "26.04.1-9") || !semverGreater("26.04.1-1", "26.04.1-0") {
		t.Error("appliance version ordering broken")
	}
}

func TestSplitDDLog(t *testing.T) {
	in := "==> stick: /dev/sda\n==> writing the image…\n" +
		"104857600 bytes (105 MB, 100 MiB) copied, 1 s, 105 MB/s\r" +
		"209715200 bytes (210 MB, 200 MiB) copied, 2 s, 105 MB/s\r" +
		"314572800 bytes (315 MB, 300 MiB) copied, 3 s, 105 MB/s\n" +
		"75+1 records in\n\n==> Done. Reboot to start the new image.\n"
	lines, n := splitDDLog(in)
	if n != 314572800 {
		t.Errorf("bytes = %d", n)
	}
	want := []string{"==> stick: /dev/sda", "==> writing the image…",
		"314572800 bytes (315 MB, 300 MiB) copied, 3 s, 105 MB/s",
		"75+1 records in", "==> Done. Reboot to start the new image."}
	if len(lines) != len(want) {
		t.Fatalf("lines = %q", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q want %q", i, lines[i], want[i])
		}
	}
}

func TestMatchPublishedChecksum(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/x.iso.sha256"
	digest := []byte{0xde, 0xad, 0xbe, 0xef}
	os.WriteFile(p, []byte("DEADBEEF  x.iso\n"), 0644)
	if err := matchPublishedChecksum(p, digest); err != nil {
		t.Errorf("matching (case-insensitive) checksum rejected: %v", err)
	}
	os.WriteFile(p, []byte("00adbeef  x.iso\n"), 0644)
	if matchPublishedChecksum(p, digest) == nil {
		t.Error("mismatching checksum accepted")
	}
	os.WriteFile(p, nil, 0644)
	if matchPublishedChecksum(p, digest) == nil {
		t.Error("empty checksum file accepted")
	}
}

func TestApplianceWriteMetaRoundTrip(t *testing.T) {
	m := applianceWriteMeta{Version: "26.04.1-3", Total: 1668878336, Mode: "reboot", Disk: "sdc", Baseline: 123456}
	f := strings.Split(strings.TrimSpace(m.String()), "\n")
	if len(f) != 5 || f[0] != "26.04.1-3" || f[2] != "reboot" || f[3] != "sdc" || f[4] != "123456" {
		t.Errorf("meta layout changed: %q", f)
	}
}

func TestDownloadApplianceFile(t *testing.T) {
	payload := bytes.Repeat([]byte("znas"), 3<<20/4) // 3 MiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()
	dest := t.TempDir() + "/img.iso"
	var last int64
	if err := downloadApplianceFile(context.Background(), srv.URL, dest, func(n int64) { last = n }); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if !bytes.Equal(got, payload) || last != int64(len(payload)) {
		t.Errorf("got %d bytes, progress %d, want %d", len(got), last, len(payload))
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Error(".part left behind")
	}
}

func TestPickApplianceStagingPool(t *testing.T) {
	const img = 1667231744
	out := "tank\t/mnt/tank\tyes\toff\t500000000000\n" +
		"big\t/mnt/big\tyes\toff\t2000000000000\n" +
		"ro\t/mnt/ro\tyes\ton\t9000000000000\n" +
		"locked\t/mnt/locked\tno\toff\t9000000000000\n" +
		"legacy\tlegacy\tyes\toff\t9000000000000\n" +
		"sick\t/mnt/sick\tyes\toff\t9000000000000\n" +
		"tiny\t/mnt/tiny\tyes\toff\t2000000000\n"
	health := map[string]bool{"tank": true, "big": true, "ro": true, "locked": true, "legacy": true, "tiny": true, "sick": false}
	pools := parseZFSPoolRoots(out, health)
	if len(pools) != 7 {
		t.Fatalf("parsed %d pools", len(pools))
	}
	p := pickApplianceStagingPool(pools, img)
	if p == nil || p.Name != "big" {
		t.Fatalf("want big (most free, healthy, mounted, writable), got %+v", p)
	}
	// Read-only, unmounted/locked, legacy mountpoint, unhealthy and too-small
	// pools are never picked; with none left the stick is used.
	if p := pickApplianceStagingPool(pools[2:], img); p != nil {
		t.Errorf("no eligible pool expected, got %s", p.Name)
	}
	if pickApplianceStagingPool(nil, img) != nil {
		t.Error("no pools must mean the stick")
	}
}

func TestBlockDiskOf(t *testing.T) {
	root := t.TempDir()
	dev := root + "/devices/pci0/usb1/host6/block/sdc"
	os.MkdirAll(dev+"/sdc1", 0755)
	os.WriteFile(dev+"/sdc1/partition", []byte("1\n"), 0644)
	cls := root + "/class/block"
	os.MkdirAll(cls, 0755)
	os.Symlink(dev, cls+"/sdc")
	os.Symlink(dev+"/sdc1", cls+"/sdc1")
	for in, want := range map[string]string{"sdc1": "sdc", "sdc": "sdc", "nope": ""} {
		if got := blockDiskOf(in, cls); got != want {
			t.Errorf("blockDiskOf(%q) = %q, want %q", in, got, want)
		}
	}
}
