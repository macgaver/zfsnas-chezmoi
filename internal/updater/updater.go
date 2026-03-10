// Package updater implements GitHub release checking and binary self-update.
package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const repoAPI = "https://api.github.com/repos/macgaver/zfsnas-chezmoi/releases/latest"

// CheckLatest calls the GitHub Releases API and returns the latest tag and
// the download URL for the asset matching the current OS/architecture.
func CheckLatest() (tag, downloadURL string, err error) {
	resp, err := http.Get(repoAPI)
	if err != nil {
		return "", "", fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decode response: %w", err)
	}

	tag = release.TagName
	// Match the asset by OS + architecture suffix, e.g. "zfsnas-linux-amd64".
	// Fall back to any asset containing the binary name "zfsnas".
	suffix := "linux-" + runtime.GOARCH
	for _, a := range release.Assets {
		if strings.Contains(a.Name, suffix) {
			downloadURL = a.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		for _, a := range release.Assets {
			if strings.Contains(strings.ToLower(a.Name), "zfsnas") {
				downloadURL = a.BrowserDownloadURL
				break
			}
		}
	}
	// Not finding a download asset is non-fatal for a version check — the caller
	// can decide whether to offer an update based on update_available alone.
	return tag, downloadURL, nil
}

// Download streams the binary at url into a temporary file inside destDir.
// Returns the temp file path on success; the caller must clean up on failure.
func Download(url, destDir string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(destDir, "zfsnas-update-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	n, copyErr := io.Copy(tmp, resp.Body)
	tmp.Close()
	if copyErr != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("write: %w", copyErr)
	}
	if n == 0 {
		os.Remove(tmpPath)
		return "", fmt.Errorf("download produced an empty file")
	}
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("chmod: %w", err)
	}
	return tmpPath, nil
}

// Replace atomically replaces destPath with the file at tmpPath.
// Both paths must be on the same filesystem for the rename to be atomic.
func Replace(tmpPath, destPath string) error {
	return os.Rename(tmpPath, destPath)
}

// Restart replaces the current process image with the binary at exePath via
// syscall.Exec. Under systemd with Restart=always the service comes straight back.
func Restart(exePath string) error {
	return syscall.Exec(exePath, os.Args, os.Environ())
}

// ExePath returns the absolute, symlink-resolved path to the running executable.
func ExePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
