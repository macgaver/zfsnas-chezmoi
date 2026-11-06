package system

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FolderEntry is one node in the scanned folder tree.
type FolderEntry struct {
	Name      string         `json:"name"`
	Path      string         `json:"path"`       // relative to dataset mountpoint root
	SizeBytes int64          `json:"size_bytes"` // total including all descendants
	Children  []*FolderEntry `json:"children,omitempty"`
}

// DatasetFolderUsage holds the complete scan result for one dataset.
type DatasetFolderUsage struct {
	Dataset    string       `json:"dataset"`
	Mountpoint string       `json:"mountpoint"`
	ScannedAt  int64        `json:"scanned_at"` // Unix timestamp
	Root       *FolderEntry `json:"root"`
}

// scanMu guards concurrent scans per dataset (key = dataset name).
var scanMu sync.Map

// ScanDatasetFolders runs `du -b -d 6 <mountpoint>` and builds a folder tree.
// Returns the result and saves it to configDir/folder_usage/<encoded>.json.
func ScanDatasetFolders(dataset, mountpoint, configDir string) (*DatasetFolderUsage, error) {
	// Prevent concurrent scans of the same dataset.
	if _, loaded := scanMu.LoadOrStore(dataset, true); loaded {
		return nil, fmt.Errorf("scan already in progress for %s", dataset)
	}
	defer scanMu.Delete(dataset)

	out, err := exec.Command("sudo", "du", "-b", "-d", "6", mountpoint).Output()
	if err != nil {
		// du exits non-zero when it hits permission errors on some dirs; use partial output.
		if len(out) == 0 {
			return nil, fmt.Errorf("du failed: %w", err)
		}
	}

	byPath := make(map[string]int64)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		if err != nil {
			continue
		}
		byPath[filepath.Clean(parts[1])] = size
	}

	root := buildFolderTree(filepath.Clean(mountpoint), byPath)
	usage := &DatasetFolderUsage{
		Dataset:    dataset,
		Mountpoint: mountpoint,
		ScannedAt:  time.Now().Unix(),
		Root:       root,
	}

	if err := saveFolderUsage(configDir, usage); err != nil {
		return nil, fmt.Errorf("save folder usage: %w", err)
	}
	return usage, nil
}

// LoadFolderUsage loads a previously saved scan from disk.
// Returns nil, nil if no scan exists yet.
func LoadFolderUsage(configDir, dataset string) (*DatasetFolderUsage, error) {
	path := folderUsagePath(configDir, dataset)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var usage DatasetFolderUsage
	if err := json.Unmarshal(b, &usage); err != nil {
		return nil, err
	}
	return &usage, nil
}

func saveFolderUsage(configDir string, usage *DatasetFolderUsage) error {
	dir := filepath.Join(configDir, "folder_usage")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	b, err := json.Marshal(usage)
	if err != nil {
		return err
	}
	return os.WriteFile(folderUsagePath(configDir, usage.Dataset), b, 0640)
}

func folderUsagePath(configDir, dataset string) string {
	// Replace path separators so the dataset name is a valid filename.
	encoded := strings.ReplaceAll(dataset, "/", "__")
	return filepath.Join(configDir, "folder_usage", encoded+".json")
}

// buildFolderTree constructs the root FolderEntry from the du path→size map.
func buildFolderTree(mountpoint string, byPath map[string]int64) *FolderEntry {
	root := &FolderEntry{
		Name:      filepath.Base(mountpoint),
		Path:      "/",
		SizeBytes: byPath[mountpoint],
	}
	populateChildren(root, mountpoint, byPath)
	return root
}

func populateChildren(node *FolderEntry, absPath string, byPath map[string]int64) {
	for p, size := range byPath {
		if p == absPath {
			continue
		}
		if filepath.Dir(p) == absPath {
			rel := "/" + strings.TrimPrefix(p, absPath+"/")
			child := &FolderEntry{
				Name:      filepath.Base(p),
				Path:      rel,
				SizeBytes: size,
			}
			populateChildren(child, p, byPath)
			node.Children = append(node.Children, child)
		}
	}
	sort.Slice(node.Children, func(i, j int) bool {
		return node.Children[i].SizeBytes > node.Children[j].SizeBytes
	})
}
