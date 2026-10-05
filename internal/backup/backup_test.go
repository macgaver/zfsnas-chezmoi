package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func init() { iters = 20_000 } // keep tests fast; Open accepts >= 10 000

// RFC 7914 §11 / RFC 6070-style vector for PBKDF2-HMAC-SHA256 (P="password", S="salt", c=1).
func TestPBKDF2Vector(t *testing.T) {
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("pbkdf2 c=1: %s", got)
	}
	got = hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 2, 32))
	want = "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	if got != want {
		t.Fatalf("pbkdf2 c=2: %s", got)
	}
}

func TestSealOpen(t *testing.T) {
	pw := "correct horse battery staple"
	data := []byte("hello znas")
	sealed, err := Seal(pw, data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(pw, sealed)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("round trip: %v %q", err, got)
	}
	if _, err := Open("wrong password!!", sealed); !errors.Is(err, ErrBadPassword) {
		t.Errorf("wrong password: %v", err)
	}
	for _, i := range []int{len(magic) + 2, len(magic) + 10, len(sealed) - 1} { // iters, salt, tag
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 1
		if _, err := Open(pw, bad); err == nil {
			t.Errorf("tamper at byte %d not detected", i)
		}
	}
	if _, err := Open(pw, []byte("PK\x03\x04 not a backup")); !errors.Is(err, ErrNotBackup) {
		t.Errorf("not a backup: %v", err)
	}
	if _, err := Seal("short", data); err == nil {
		t.Error("short password accepted")
	}
}

func TestBuildExtract(t *testing.T) {
	m := Manifest{ZNASVersion: "6.10.5", SourceType: "host", Hostname: "nas", CreatedAt: time.Unix(1700000000, 0)}
	files := map[string][]byte{
		"config/users.json":       []byte(`[]`),
		"config/keys/a.key":       {1, 2, 3},
		"system/accounts.json":    []byte(`[]`),
		"incus/networks/br0.yaml": []byte("name: br0\n"),
	}
	arch, err := Build(m, files)
	if err != nil {
		t.Fatal(err)
	}
	got, out, err := Extract(arch)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "nas" || got.Format != FormatVersion || len(out) != len(files) {
		t.Fatalf("manifest/files: %+v %d", got, len(out))
	}
	if !bytes.Equal(out["config/keys/a.key"], []byte{1, 2, 3}) {
		t.Error("content changed")
	}
}

func TestPathsRejected(t *testing.T) {
	for _, p := range []string{"/etc/passwd", "../x", "config/../../etc/x", "config", "other/x", `config\x`, "config//x", ""} {
		if _, err := Build(Manifest{}, map[string][]byte{p: nil}); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
}

// rawArchive builds a tar.gz by hand so tests can write manifests that lie.
func rawArchive(t *testing.T, manifest string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(n, c string) {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0600, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	add("manifest.json", manifest)
	for n, c := range files {
		add(n, c)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestExtractDetectsCorruption(t *testing.T) {
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	ok := `{"format":1,"files":{"config/a.json":"` + sum("aaaa") + `"}}`
	if _, _, err := Extract(rawArchive(t, ok, map[string]string{"config/a.json": "aaaa"})); err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	cases := map[string][]byte{
		"hash mismatch":  rawArchive(t, ok, map[string]string{"config/a.json": "bbbb"}),
		"missing file":   rawArchive(t, ok, map[string]string{}),
		"unlisted file":  rawArchive(t, ok, map[string]string{"config/a.json": "aaaa", "config/b.json": "x"}),
		"newer format":   rawArchive(t, `{"format":99,"files":{}}`, nil),
		"path traversal": rawArchive(t, `{"format":1,"files":{}}`, map[string]string{"config/../../etc/x": "x"}),
		"garbage":        []byte("garbage"),
	}
	for name, arch := range cases {
		if _, _, err := Extract(arch); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
