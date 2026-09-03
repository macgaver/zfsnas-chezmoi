// Package updater implements GitHub release checking, signature verification,
// and binary self-update.
package updater

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// metaClient is used for the small metadata requests (release JSON, .sig
// files). It carries a timeout because a hung connection would otherwise block
// forever: net/http's default client has none, and the appliance runs its
// first-boot check on a network that may be half up. Binary downloads keep
// using the default client — a whole-request timeout is the wrong tool for a
// 27 MB body on a slow link.
var metaClient = &http.Client{Timeout: 30 * time.Second}

const repoAPI = "https://api.github.com/repos/macgaver/zfsnas-chezmoi/releases/latest"
const repoReleasesAPI = "https://api.github.com/repos/macgaver/zfsnas-chezmoi/releases"
const repoTagAPI = "https://api.github.com/repos/macgaver/zfsnas-chezmoi/releases/tags/"

// ReleaseInfo holds the result of CheckLatest.
type ReleaseInfo struct {
	Tag         string
	DownloadURL string
	SigURL      string // URL of the .sig file (cosign signature of the binary)
}

// ReleaseSummary is a single GitHub release entry returned by CheckReleases.
// Prerelease is always false in the output — pre-releases are filtered at the source.
type ReleaseSummary struct {
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	Body        string `json:"body"`         // raw markdown from GitHub
	PublishedAt string `json:"published_at"` // RFC3339
	DownloadURL string `json:"download_url"`
	SigURL      string `json:"sig_url"`
	Prerelease  bool   `json:"prerelease"` // always false — pre-releases are filtered out
}

// CheckLatest calls the GitHub Releases API and returns the latest release info.
func CheckLatest() (ReleaseInfo, error) {
	resp, err := metaClient.Get(repoAPI)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ReleaseInfo{}, fmt.Errorf("decode response: %w", err)
	}

	info := ReleaseInfo{Tag: release.TagName}
	suffix := "linux-" + runtime.GOARCH

	for _, a := range release.Assets {
		name := a.Name
		switch {
		case strings.HasSuffix(name, ".sig"):
			info.SigURL = a.BrowserDownloadURL
		case strings.Contains(name, suffix):
			info.DownloadURL = a.BrowserDownloadURL
		}
	}
	// Fallback: any asset containing "zfsnas" that isn't a .sig
	if info.DownloadURL == "" {
		for _, a := range release.Assets {
			n := strings.ToLower(a.Name)
			if strings.Contains(n, "zfsnas") && !strings.HasSuffix(n, ".sig") {
				info.DownloadURL = a.BrowserDownloadURL
				break
			}
		}
	}
	return info, nil
}

// VerifyRelease downloads the binary and its .sig, then verifies the signature
// against the embedded public key. Returns (true, nil) when valid.
func VerifyRelease(info ReleaseInfo) (bool, error) {
	if strings.TrimSpace(cosignPublicKey) == "" {
		return false, fmt.Errorf("no signing key configured in binary")
	}
	if info.SigURL == "" || info.DownloadURL == "" {
		return false, fmt.Errorf("release has no signature asset")
	}

	// Download the .sig file (base64-encoded DER ECDSA signature, ~100 bytes).
	sigB64, err := downloadText(info.SigURL)
	if err != nil {
		return false, fmt.Errorf("download sig: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return false, fmt.Errorf("decode sig: %w", err)
	}

	// Parse the embedded public key.
	block, _ := pem.Decode([]byte(cosignPublicKey))
	if block == nil {
		return false, fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key is not ECDSA")
	}

	// Stream-download the binary and compute its SHA256 on the fly.
	resp, err := http.Get(info.DownloadURL)
	if err != nil {
		return false, fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("download binary: HTTP %d", resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return false, fmt.Errorf("hash binary: %w", err)
	}
	digest := h.Sum(nil)

	return ecdsa.VerifyASN1(ecPub, digest, sigBytes), nil
}

// VerifyDownloadedBinary verifies the signature of an already-downloaded binary
// at path against the .sig at sigURL.
func VerifyDownloadedBinary(path, sigURL string) error {
	if strings.TrimSpace(cosignPublicKey) == "" {
		return fmt.Errorf("no signing key configured in binary")
	}

	sigB64, err := downloadText(sigURL)
	if err != nil {
		return fmt.Errorf("download sig: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}

	block, _ := pem.Decode([]byte(cosignPublicKey))
	if block == nil {
		return fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	if !ecdsa.VerifyASN1(ecPub, h.Sum(nil), sigBytes) {
		return fmt.Errorf("signature invalid: binary does not match release key")
	}
	return nil
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
func Replace(tmpPath, destPath string) error {
	if err := os.Rename(tmpPath, destPath); err != nil {
		return err
	}
	// A power cut mid-upgrade must not leave a truncated override on disk;
	// force the rename (and the data it points at) out to the device.
	if f, err := os.OpenFile(destPath, os.O_RDONLY, 0); err == nil {
		f.Sync()
		f.Close()
	}
	return nil
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

// CheckReleases returns the latest n stable releases from GitHub.
// Pre-releases (GitHub prerelease flag == true) are always excluded even if they
// appear at the top of the releases list. We request a larger page to guarantee
// n stable results are available after filtering.
func CheckReleases(n int) ([]ReleaseSummary, error) {
	u := fmt.Sprintf("%s?per_page=%d", repoReleasesAPI, n*3)
	resp, err := metaClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var raw []struct {
		TagName     string `json:"tag_name"`
		Name        string `json:"name"`
		Body        string `json:"body"`
		PublishedAt string `json:"published_at"`
		Prerelease  bool   `json:"prerelease"`
		Assets      []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	suffix := "linux-" + runtime.GOARCH
	out := make([]ReleaseSummary, 0, n)
	for _, r := range raw {
		if r.Prerelease {
			continue // pre-releases are invisible to stable-channel users
		}
		s := ReleaseSummary{
			Tag:         r.TagName,
			Name:        r.Name,
			Body:        r.Body,
			PublishedAt: r.PublishedAt,
			Prerelease:  false,
		}
		for _, a := range r.Assets {
			switch {
			case strings.HasSuffix(a.Name, ".sig"):
				s.SigURL = a.BrowserDownloadURL
			case strings.Contains(a.Name, suffix):
				s.DownloadURL = a.BrowserDownloadURL
			}
		}
		out = append(out, s)
		if len(out) >= n {
			break
		}
	}
	return out, nil
}

// CheckRelease fetches a specific GitHub release by tag name (e.g. "v6.4.10").
func CheckRelease(tag string) (ReleaseInfo, error) {
	resp, err := http.Get(repoTagAPI + tag)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ReleaseInfo{}, fmt.Errorf("release %s not found on GitHub", tag)
	}
	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ReleaseInfo{}, fmt.Errorf("decode: %w", err)
	}

	info := ReleaseInfo{Tag: release.TagName}
	suffix := "linux-" + runtime.GOARCH
	for _, a := range release.Assets {
		switch {
		case strings.HasSuffix(a.Name, ".sig"):
			info.SigURL = a.BrowserDownloadURL
		case strings.Contains(a.Name, suffix):
			info.DownloadURL = a.BrowserDownloadURL
		}
	}
	// Fallback: any asset containing "zfsnas" that isn't a .sig
	// (covers older releases whose binary asset has no arch suffix).
	if info.DownloadURL == "" {
		for _, a := range release.Assets {
			n := strings.ToLower(a.Name)
			if strings.Contains(n, "zfsnas") && !strings.HasSuffix(n, ".sig") {
				info.DownloadURL = a.BrowserDownloadURL
				break
			}
		}
	}
	return info, nil
}

// downloadText fetches a URL and returns its body as a string.
func downloadText(url string) (string, error) {
	resp, err := metaClient.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
