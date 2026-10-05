package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// FormatVersion of the archive contents (manifest.json "format").
const FormatVersion = 1

// Allowed top-level folders inside the archive. Anything else is refused on
// extraction, so a crafted backup cannot drop files elsewhere.
var allowedRoots = map[string]bool{"config": true, "system": true, "incus": true}

// Manifest describes a backup. It is stored as manifest.json and is the only
// file read before the user confirms the import.
type Manifest struct {
	Format      int               `json:"format"`
	ZNASVersion string            `json:"znas_version"`
	SourceType  string            `json:"source_type"` // "host" | "appliance"
	Hostname    string            `json:"hostname"`
	CreatedAt   time.Time         `json:"created_at"`
	Options     ExportOptions     `json:"options"`
	Inventory   Inventory         `json:"inventory"`
	Files       map[string]string `json:"files"` // path → sha256 hex
}

// ExportOptions chosen at export.
type ExportOptions struct {
	IncludeCharts   bool `json:"include_charts"`
	IncludeAudit    bool `json:"include_audit"`
	IncludeCerts    bool `json:"include_certs"`
	IncludeHostname bool `json:"include_hostname"`
}

// Inventory summarises what is inside, for the import plan screen.
type Inventory struct {
	Users       []string       `json:"users"`
	Accounts    int            `json:"accounts"`     // Linux accounts carried
	SMBPassword int            `json:"smb_password"` // SMB password hashes carried
	SMBShares   []string       `json:"smb_shares"`
	NFSExports  []string       `json:"nfs_exports"`
	ISCSI       int            `json:"iscsi_targets"`
	Pools       []PoolRef      `json:"pools"`
	Datastores  []DatastoreRef `json:"datastores"`
	Instances   []InstanceRef  `json:"instances"`
	Networks    []string       `json:"networks"` // networks used by instances
	Features    []string       `json:"features"` // optional features in use
	Warnings    []string       `json:"warnings"` // things the export could not include
}

// PoolRef identifies a ZFS pool by name and GUID.
type PoolRef struct {
	Name string `json:"name"`
	GUID string `json:"guid"`
}

// DatastoreRef is an Incus storage pool on ZFS.
type DatastoreRef struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Source string `json:"source"` // pool/dataset
}

// InstanceRef is a VM or container.
type InstanceRef struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"` // "virtual-machine" | "container"
	Pool     string   `json:"pool"` // datastore name
	Networks []string `json:"networks"`
}

// Build packs files (path → content) and the manifest into a tar.gz. File
// hashes are computed here and written into the manifest.
func Build(m Manifest, files map[string][]byte) ([]byte, error) {
	m.Format = FormatVersion
	m.Files = map[string]string{}
	names := make([]string, 0, len(files))
	for name := range files {
		if err := checkPath(name); err != nil {
			return nil, err
		}
		names = append(names, name)
		sum := sha256.Sum256(files[name])
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	sort.Strings(names)
	manifest, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)),
			ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := write("manifest.json", manifest); err != nil {
		return nil, err
	}
	for _, name := range names {
		if err := write(name, files[name]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Extract unpacks a tar.gz made by Build, checks every path and hash, and
// returns the manifest and the files. Nothing is written to disk.
func Extract(data []byte) (Manifest, map[string][]byte, error) {
	var m Manifest
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return m, nil, fmt.Errorf("backup archive is damaged: %w", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var manifest []byte
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, nil, fmt.Errorf("backup archive is damaged: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return m, nil, fmt.Errorf("unexpected entry %q in backup", h.Name)
		}
		total += h.Size
		if total > 4*MaxFileSize {
			return m, nil, errors.New("backup archive expands to an unreasonable size")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return m, nil, fmt.Errorf("backup archive is damaged at %q", h.Name)
		}
		if h.Name == "manifest.json" {
			manifest = b
			continue
		}
		if err := checkPath(h.Name); err != nil {
			return m, nil, err
		}
		files[h.Name] = b
	}
	if manifest == nil {
		return m, nil, errors.New("backup has no manifest")
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		return m, nil, fmt.Errorf("backup manifest is unreadable: %w", err)
	}
	if m.Format > FormatVersion {
		return m, nil, fmt.Errorf("this backup was made by a newer ZNAS (format %d); update this server first", m.Format)
	}
	for name, want := range m.Files {
		b, ok := files[name]
		if !ok {
			return m, nil, fmt.Errorf("backup is missing %q", name)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return m, nil, fmt.Errorf("backup file %q is corrupted", name)
		}
	}
	for name := range files {
		if _, ok := m.Files[name]; !ok {
			return m, nil, fmt.Errorf("backup contains an unlisted file %q", name)
		}
	}
	return m, files, nil
}

// checkPath accepts only clean relative paths under the allowed roots.
func checkPath(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") ||
		path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
		return fmt.Errorf("invalid path %q in backup", name)
	}
	root := strings.SplitN(name, "/", 2)[0]
	if !allowedRoots[root] || !strings.Contains(name, "/") {
		return fmt.Errorf("unexpected path %q in backup", name)
	}
	return nil
}
