package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The MinIO-era admin name only survives once S3 is configured on RustFS.
func TestS3AdminDefault(t *testing.T) {
	cases := []struct {
		json string
		want string
	}{
		{`{"minio":{}}`, "s3admin"},                                              // never set
		{`{"minio":{"root_user":"minioadmin"}}`, "s3admin"},                      // old default, not on RustFS
		{`{"minio":{"root_user":"minioadmin","engine":"rustfs"}}`, "minioadmin"}, // real RustFS admin: kept
		{`{"minio":{"root_user":"bob"}}`, "bob"},                                 // chosen by the owner
	}
	for _, c := range cases {
		dir := t.TempDir()
		if err := Init(dir); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "config.json"), []byte(c.json), 0600)
		cfg, err := LoadAppConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.MinIO.RootUser != c.want {
			t.Errorf("%s: root_user %q, want %q", c.json, cfg.MinIO.RootUser, c.want)
		}
	}
}
