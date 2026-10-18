package handlers

import (
	"os"
	"path/filepath"
	"testing"

	"zfsnas/internal/config"
)

func TestLegacyMinIOBucketsLeft(t *testing.T) {
	cfgDir := t.TempDir()
	if err := config.Init(cfgDir); err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	app := &config.AppConfig{}
	app.MinIO.DataDir = data
	app.MinIO.LegacyMinIOBuckets = []config.S3Bucket{{Name: "bucket1"}, {Name: "photos"}}
	os.MkdirAll(filepath.Join(data, "rustfs-data"), 0755)

	os.MkdirAll(filepath.Join(data, "bucket1"), 0755)
	if n := legacyMinIOBucketsLeft(app); n != 1 {
		t.Errorf("one bucket folder left: got %d", n)
	}
	os.RemoveAll(filepath.Join(data, "bucket1"))
	os.MkdirAll(filepath.Join(data, ".minio.sys"), 0755)
	if n := legacyMinIOBucketsLeft(app); n != 2 {
		t.Errorf("only .minio.sys left: got %d, want the whole list", n)
	}
	os.RemoveAll(filepath.Join(data, ".minio.sys"))
	if n := legacyMinIOBucketsLeft(app); n != 0 || app.MinIO.LegacyMinIOBuckets != nil {
		t.Errorf("all removed: got %d, list %v (must be forgotten)", n, app.MinIO.LegacyMinIOBuckets)
	}
	// A legacy bucket that happened to be called rustfs-data never counts.
	app.MinIO.LegacyMinIOBuckets = []config.S3Bucket{{Name: "rustfs-data"}}
	if n := legacyMinIOBucketsLeft(app); n != 0 {
		t.Errorf("rustfs-data must not count as MinIO data: got %d", n)
	}
}
