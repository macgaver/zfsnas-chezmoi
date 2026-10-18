package system

// s3server.go — the optional S3 object server, RustFS (v6.10.17; replaces
// MinIO, whose open-source edition is end of life: both repositories archived,
// no binaries since 2025).
//
// The portal installs the pinned RustFS release itself: it downloads the
// static (musl) build from GitHub, checks it against the SHA-256 pinned below,
// and streams it to /usr/local/bin/rustfs. Configuration is RustFS's own
// environment file; users, buckets and policies go through the S3 and admin
// APIs (s3client.go), so no CLI tool is needed.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"zfsnas/internal/config"
)

const (
	rustfsVersion  = "1.0.2"
	rustfsBin      = "/usr/local/bin/rustfs"
	rustfsUnitPath = "/etc/systemd/system/rustfs.service"
	rustfsEnvPath  = "/etc/default/rustfs"
	rustfsHome     = "/var/lib/rustfs"
	rustfsTLSDir   = "/var/lib/rustfs/tls"
	// RustFSDataSubdir is created inside the configured dataset. Never the old
	// "minio-data": MinIO's on-disk format is not RustFS's.
	RustFSDataSubdir = "rustfs-data"
)

// rustfsZipSHA256 pins the release archives (from the release's SHA256SUMS,
// 2026-10-17). Bump together with rustfsVersion.
var rustfsZipSHA256 = map[string]string{
	"amd64": "452bf5f000507e7b91bc18f5a52c9945be7ffa4d254a3816a97e23aa76880d7d",
	"arm64": "39712ed2bcad5bbf6fbbae15abe753f0c4a726744b7383a445d6aec835140943",
}

// MinIOServiceStatus describes the S3 server daemon (name kept for the API).
type MinIOServiceStatus struct {
	Active bool   `json:"active"`
	Status string `json:"status"`
}

// S3UserInfo is returned by ListS3Users.
type S3UserInfo struct {
	AccessKey string `json:"accessKey"`
	Status    string `json:"status"`
}

// S3BucketCreateOptions contains parameters for creating a new S3 bucket.
type S3BucketCreateOptions struct {
	Name       string
	Versioning string // "off", "enabled", "suspended"
	ObjectLock bool
	Quota      string // human string e.g. "50G", "" = unlimited
	AnonAccess string // "none", "download", "public"
}

// S3ServerInstalled reports whether the RustFS binary is present.
func S3ServerInstalled() bool { return binaryInstalled("rustfs") }

// S3ServerVersion is the installed RustFS version ("" when absent).
func S3ServerVersion() string {
	out, err := exec.Command(rustfsBin, "--version").Output()
	if err != nil {
		return ""
	}
	// First line: "rustfs 1.0.2" (or similar); keep the last word.
	f := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

func sudoRun(args ...string) error {
	if out, err := exec.Command("sudo", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// sudoTee writes data to a fixed path through `sudo tee` (the path must match
// a sudoers entry exactly).
func sudoTee(dst string, data io.Reader) error {
	cmd := exec.Command("sudo", "/usr/bin/tee", dst)
	cmd.Stdin = data
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("write %s: %w: %s", dst, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// ── Install / uninstall ──────────────────────────────────────────────────────

// InstallS3Server downloads, verifies and installs RustFS, creates its account
// and service. The service is enabled but only started once configured.
func InstallS3Server() error {
	arch := runtime.GOARCH
	want, ok := rustfsZipSHA256[arch]
	if !ok {
		return fmt.Errorf("RustFS has no build for this CPU (%s)", arch)
	}
	cpu := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[arch]
	url := fmt.Sprintf("https://github.com/rustfs/rustfs/releases/download/%s/rustfs-linux-%s-musl-v%s.zip",
		rustfsVersion, cpu, rustfsVersion)

	tmp, err := os.MkdirTemp("", "znas-rustfs-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	zipPath := filepath.Join(tmp, "rustfs.zip")
	if err := downloadVerified(url, zipPath, want); err != nil {
		return err
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open RustFS archive: %w", err)
	}
	defer zr.Close()
	var bin *zip.File
	for _, f := range zr.File {
		if filepath.Base(f.Name) == "rustfs" && !f.FileInfo().IsDir() {
			bin = f
		}
	}
	if bin == nil {
		return fmt.Errorf("the RustFS archive has no rustfs binary")
	}
	rc, err := bin.Open()
	if err != nil {
		return err
	}
	err = sudoTee(rustfsBin, rc)
	rc.Close()
	if err != nil {
		return err
	}
	if err := sudoRun("chmod", "755", rustfsBin); err != nil {
		return err
	}
	ForgetBinaryPresence("rustfs")
	return EnsureS3Service()
}

// downloadVerified fetches url to dst and checks its SHA-256.
func downloadVerified(url, dst, wantSHA string) error {
	client := &http.Client{Timeout: 15 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download RustFS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download RustFS: %s returned HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("download RustFS: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA {
		return fmt.Errorf("the RustFS download does not match its pinned checksum (got %s) — refusing to install it", got)
	}
	return nil
}

// UninstallS3Server stops and removes RustFS. Data folders are kept.
func UninstallS3Server() error {
	exec.Command("sudo", "systemctl", "stop", "rustfs").Run()    //nolint:errcheck
	exec.Command("sudo", "systemctl", "disable", "rustfs").Run() //nolint:errcheck
	for _, f := range []string{rustfsBin, rustfsUnitPath, rustfsEnvPath} {
		exec.Command("sudo", "rm", "-f", f).Run() //nolint:errcheck
	}
	exec.Command("sudo", "systemctl", "daemon-reload").Run() //nolint:errcheck
	ForgetBinaryPresence("rustfs")
	return nil
}

// ── Service ──────────────────────────────────────────────────────────────────

const rustfsUnit = `[Unit]
Description=RustFS S3 object storage (ZNAS)
Documentation=https://rustfs.com/docs/
Wants=network-online.target
After=network-online.target zfs-mount.service
AssertFileIsExecutable=/usr/local/bin/rustfs

[Service]
Type=notify
NotifyAccess=main
User=rustfs
Group=rustfs
WorkingDirectory=/var/lib/rustfs
EnvironmentFile=/etc/default/rustfs
ExecStart=/usr/local/bin/rustfs server
LimitNOFILE=1048576
TasksMax=infinity
Restart=always
RestartSec=10s
TimeoutStartSec=120s
TimeoutStopSec=45s
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

// EnsureS3Service makes sure the account, home, TLS folder and enabled unit
// exist. Idempotent; run before any apply / start / restart (lesson from
// MinIO on the appliance, whose RAM root loses all of it at each boot).
func EnsureS3Service() error {
	if !S3ServerInstalled() {
		return fmt.Errorf("RustFS is not installed (Requisites → Optional Features)")
	}
	if exec.Command("id", "rustfs").Run() != nil {
		// Argument order must match the sudoers rule exactly.
		if err := sudoRun("useradd", "--system", "--home-dir", rustfsHome,
			"--shell", "/usr/sbin/nologin", "rustfs"); err != nil {
			return err
		}
	}
	if err := sudoRun("mkdir", "-p", rustfsTLSDir); err != nil {
		return err
	}
	if err := sudoRun("chown", "-R", "rustfs:rustfs", rustfsHome); err != nil {
		return err
	}
	cur, _ := os.ReadFile(rustfsUnitPath)
	if string(cur) != rustfsUnit {
		if err := sudoTee(rustfsUnitPath, strings.NewReader(rustfsUnit)); err != nil {
			return err
		}
		if err := sudoRun("systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := sudoRun("systemctl", "enable", "rustfs"); err != nil {
			return err
		}
	}
	return nil
}

// GetMinIOServiceStatus reports the S3 server service state.
func GetMinIOServiceStatus() MinIOServiceStatus {
	out, err := exec.Command("systemctl", "is-active", "rustfs").Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		status = "inactive"
	}
	return MinIOServiceStatus{Active: status == "active", Status: status}
}

func S3ServiceAction(action string) error {
	if action != "stop" {
		if err := EnsureS3Service(); err != nil {
			return err
		}
	}
	return sudoRun("systemctl", action, "rustfs")
}

// ── Configuration ────────────────────────────────────────────────────────────

// envQuote quotes a value for a systemd EnvironmentFile.
func envQuote(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", "")
	return `"` + v + `"`
}

// S3DataDir is where RustFS keeps its data for a configuration.
func S3DataDir(cfg *config.MinIOConfig) string {
	return filepath.Join(cfg.DataDir, RustFSDataSubdir)
}

// buildRustFSEnv renders /etc/default/rustfs (pure; unit-tested).
func buildRustFSEnv(cfg *config.MinIOConfig) string {
	var b strings.Builder
	w := func(k, v string) { fmt.Fprintf(&b, "%s=%s\n", k, envQuote(v)) }
	w("RUSTFS_ACCESS_KEY", cfg.RootUser)
	w("RUSTFS_SECRET_KEY", cfg.RootPassword)
	w("RUSTFS_VOLUMES", S3DataDir(cfg))
	w("RUSTFS_ADDRESS", fmt.Sprintf(":%d", cfg.Port))
	w("RUSTFS_CONSOLE_ENABLE", "true")
	w("RUSTFS_CONSOLE_ADDRESS", fmt.Sprintf(":%d", cfg.ConsolePort))
	w("RUSTFS_REGION", cfg.Region)
	if host := serverDomain(cfg.ServerURL); host != "" {
		w("RUSTFS_SERVER_DOMAINS", host)
	}
	if cfg.TLS {
		w("RUSTFS_TLS_PATH", rustfsTLSDir)
	}
	return b.String()
}

var ipLike = regexp.MustCompile(`^[0-9.:\[\]]+$`)

// serverDomain extracts a host name for virtual-hosted-style requests from
// the configured server URL (IP addresses and empty values give "").
func serverDomain(serverURL string) string {
	u := strings.TrimSpace(serverURL)
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	u = strings.SplitN(u, "/", 2)[0]
	if h, _, ok := strings.Cut(u, ":"); ok && !strings.Contains(u, "]") {
		u = h
	}
	if u == "" || ipLike.MatchString(u) || u == "localhost" {
		return ""
	}
	return u
}

// ApplyS3Config writes the TLS files and environment, prepares the data
// folder and (re)starts RustFS, then waits until its API answers.
func ApplyS3Config(cfg *config.MinIOConfig, configDir string) error {
	if err := EnsureS3Service(); err != nil {
		return err
	}
	if cfg.TLS {
		if cfg.TLSCertName == "" || cfg.TLSCertName == "auto" {
			if err := installGeneratedS3Cert(); err != nil {
				return fmt.Errorf("enable TLS: %w", err)
			}
		} else {
			c := filepath.Join(configDir, "certs", cfg.TLSCertName+".crt")
			k := filepath.Join(configDir, "certs", cfg.TLSCertName+".key")
			if err := installS3CertFiles(c, k); err != nil {
				return fmt.Errorf("install certificate %q: %w", cfg.TLSCertName, err)
			}
		}
	} else {
		exec.Command("sudo", "rm", "-f", filepath.Join(rustfsTLSDir, "rustfs_cert.pem")).Run() //nolint:errcheck
		exec.Command("sudo", "rm", "-f", filepath.Join(rustfsTLSDir, "rustfs_key.pem")).Run()  //nolint:errcheck
	}

	data := S3DataDir(cfg)
	if err := sudoRun("mkdir", "-p", data); err != nil {
		return err
	}
	if err := sudoRun("chown", "-R", "rustfs:rustfs", data); err != nil {
		return err
	}
	if err := sudoTee(rustfsEnvPath, strings.NewReader(buildRustFSEnv(cfg))); err != nil {
		return err
	}
	if err := sudoRun("chown", "root:rustfs", rustfsEnvPath); err != nil {
		return err
	}
	if err := sudoRun("chmod", "640", rustfsEnvPath); err != nil {
		return err
	}
	// A former MinIO would hold the same ports: switch it off for good.
	if _, err := os.Stat("/etc/systemd/system/minio.service"); err == nil {
		exec.Command("sudo", "systemctl", "stop", "minio").Run()    //nolint:errcheck
		exec.Command("sudo", "systemctl", "disable", "minio").Run() //nolint:errcheck
	}
	if err := sudoRun("systemctl", "restart", "rustfs"); err != nil {
		return err
	}
	return waitS3Ready(cfg, 60*time.Second)
}

// waitS3Ready polls the API with the admin credentials until it answers.
func waitS3Ready(cfg *config.MinIOConfig, timeout time.Duration) error {
	c := S3AdminClient(cfg)
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, err := c.ListBuckets(); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("RustFS did not become ready in %s: %v", timeout, last)
}

// S3AdminClient is a client for the local server with the admin credentials.
func S3AdminClient(cfg *config.MinIOConfig) *S3Client {
	return NewLocalS3Client(cfg.Port, cfg.TLS, cfg.RootUser, cfg.RootPassword, cfg.Region)
}

// ReapplyS3AtStartup rebuilds a configured RustFS whose unit is missing (a
// USB appliance's RAM root loses it at every boot), once its dataset is
// mounted. A no-op on regular installs.
func ReapplyS3AtStartup(cfg *config.MinIOConfig, configDir string) {
	if !cfg.Enabled || cfg.Engine != "rustfs" || cfg.DataDir == "" || !S3ServerInstalled() {
		return
	}
	if _, err := os.Stat(rustfsUnitPath); err == nil {
		return
	}
	for i := 0; ; i++ {
		out, err := exec.Command("sudo", "zfs", "get", "-H", "-o", "value", "mounted", cfg.DatasetPath).Output()
		if cfg.DatasetPath == "" || (err == nil && strings.TrimSpace(string(out)) == "yes") {
			break
		}
		if i >= 60 {
			fmt.Printf("[s3] %s is not mounted after 5 minutes — S3 service not started\n", cfg.DatasetPath)
			return
		}
		time.Sleep(5 * time.Second)
	}
	if err := ApplyS3Config(cfg, configDir); err != nil {
		fmt.Printf("[s3] could not restore the S3 service at startup: %v\n", err)
		return
	}
	fmt.Println("[s3] S3 service restored from the saved configuration")
}

// ── TLS ──────────────────────────────────────────────────────────────────────

func installGeneratedS3Cert() error {
	tmp, err := os.MkdirTemp("", "znas-s3-tls-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	c, k := filepath.Join(tmp, "cert.pem"), filepath.Join(tmp, "key.pem")
	if err := generateS3Cert(c, k); err != nil {
		return err
	}
	return installS3CertFiles(c, k)
}

func installS3CertFiles(certFile, keyFile string) error {
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	if err := sudoTee(filepath.Join(rustfsTLSDir, "rustfs_cert.pem"), bytes.NewReader(cert)); err != nil {
		return err
	}
	if err := sudoTee(filepath.Join(rustfsTLSDir, "rustfs_key.pem"), bytes.NewReader(key)); err != nil {
		return err
	}
	if err := sudoRun("chown", "-R", "rustfs:rustfs", rustfsHome); err != nil {
		return err
	}
	return sudoRun("chmod", "640", filepath.Join(rustfsTLSDir, "rustfs_key.pem"))
}

// ── Users ────────────────────────────────────────────────────────────────────

func ListS3Users(cfg *config.MinIOConfig) ([]S3UserInfo, error) {
	m, err := S3AdminClient(cfg).ListUsers()
	if err != nil {
		return nil, err
	}
	users := make([]S3UserInfo, 0, len(m))
	for k, st := range m {
		if st == "" {
			st = "enabled"
		}
		users = append(users, S3UserInfo{AccessKey: k, Status: st})
	}
	sortS3Users(users)
	return users, nil
}

func sortS3Users(u []S3UserInfo) {
	for i := 1; i < len(u); i++ {
		for j := i; j > 0 && u[j].AccessKey < u[j-1].AccessKey; j-- {
			u[j], u[j-1] = u[j-1], u[j]
		}
	}
}

func CreateS3User(cfg *config.MinIOConfig, accessKey, secretKey string) error {
	return S3AdminClient(cfg).PutUser(accessKey, secretKey, true)
}

func DeleteS3User(cfg *config.MinIOConfig, accessKey string) error {
	return S3AdminClient(cfg).RemoveUser(accessKey)
}

func SetS3UserStatus(cfg *config.MinIOConfig, accessKey string, enabled bool) error {
	return S3AdminClient(cfg).SetUserStatus(accessKey, enabled)
}

// SetS3UserPassword changes a user's secret; its status and policies stay.
func SetS3UserPassword(cfg *config.MinIOConfig, accessKey, newSecret string) error {
	c := S3AdminClient(cfg)
	enabled := true
	if m, err := c.ListUsers(); err == nil && m[accessKey] == "disabled" {
		enabled = false
	}
	return c.PutUser(accessKey, newSecret, enabled)
}

// ── Buckets ──────────────────────────────────────────────────────────────────

// parseQuotaBytes turns "50G", "50GiB", "1.5T", "512MB" or a byte count into
// bytes (binary units, as the UI shows them). "" / "0" = no quota.
func parseQuotaBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.ReplaceAll(s, " ", "")
	if s == "" || s == "0" {
		return 0, nil
	}
	num := strings.TrimRight(s, "KMGTPIB")
	unit := s[len(num):]
	v, err := strconv.ParseFloat(num, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid quota %q (use e.g. 500G or 2T)", s)
	}
	mult := map[string]float64{"": 1, "B": 1, "K": 1 << 10, "KB": 1 << 10, "KIB": 1 << 10,
		"M": 1 << 20, "MB": 1 << 20, "MIB": 1 << 20, "G": 1 << 30, "GB": 1 << 30, "GIB": 1 << 30,
		"T": 1 << 40, "TB": 1 << 40, "TIB": 1 << 40, "P": 1 << 50, "PB": 1 << 50, "PIB": 1 << 50}[unit]
	if mult == 0 {
		return 0, fmt.Errorf("invalid quota unit in %q (use K, M, G, T or P)", s)
	}
	return int64(v * mult), nil
}

func anonPolicy(bucket, access string) []byte {
	actions := []string{"s3:GetObject"}
	if access == "public" {
		actions = []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}
	}
	p := map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{
			map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": []string{"*"}},
				"Action": []string{"s3:GetBucketLocation", "s3:ListBucket"}, "Resource": []string{"arn:aws:s3:::" + bucket}},
			map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": []string{"*"}},
				"Action": actions, "Resource": []string{"arn:aws:s3:::" + bucket + "/*"}},
		},
	}
	b, _ := json.Marshal(p)
	return b
}

func CreateS3Bucket(cfg *config.MinIOConfig, opts S3BucketCreateOptions) error {
	c := S3AdminClient(cfg)
	if err := c.MakeBucket(opts.Name, opts.ObjectLock); err != nil {
		return fmt.Errorf("create bucket: %w", err)
	}
	if !opts.ObjectLock && (opts.Versioning == "enabled" || opts.Versioning == "suspended") {
		if err := c.SetVersioning(opts.Name, opts.Versioning); err != nil {
			return fmt.Errorf("versioning: %w", err)
		}
	}
	if err := S3ApplyQuota(cfg, opts.Name, opts.Quota); err != nil {
		return err
	}
	return S3ApplyAnonAccess(cfg, opts.Name, opts.AnonAccess)
}

func DeleteS3Bucket(cfg *config.MinIOConfig, name string) error {
	c := S3AdminClient(cfg)
	if err := c.DeleteBucketForce(name); err != nil {
		return err
	}
	_ = c.RemovePolicy("zfsnas-" + name)
	return nil
}

func S3ApplyVersioning(cfg *config.MinIOConfig, bucket, versioning string) error {
	if versioning != "enabled" && versioning != "suspended" {
		return nil
	}
	return S3AdminClient(cfg).SetVersioning(bucket, versioning)
}

func S3ApplyQuota(cfg *config.MinIOConfig, bucket, quota string) error {
	n, err := parseQuotaBytes(quota)
	if err != nil {
		return err
	}
	return S3AdminClient(cfg).SetBucketQuota(bucket, n)
}

func S3ApplyAnonAccess(cfg *config.MinIOConfig, bucket, access string) error {
	c := S3AdminClient(cfg)
	if access == "download" || access == "public" {
		return c.PutBucketPolicy(bucket, anonPolicy(bucket, access))
	}
	return c.DeleteBucketPolicy(bucket)
}

// ApplyBucketUserPolicy gives exactly userKeys read/write access to the bucket
// through the "zfsnas-<bucket>" policy, detaching it from prevKeys no longer listed.
func ApplyBucketUserPolicy(cfg *config.MinIOConfig, bucket string, userKeys, prevKeys []string) error {
	c := S3AdminClient(cfg)
	policy := "zfsnas-" + bucket
	keep := map[string]bool{}
	for _, k := range userKeys {
		keep[k] = true
	}
	for _, k := range prevKeys {
		if !keep[k] {
			_ = c.DetachPolicy(k, policy) // the user may already be gone
		}
	}
	if len(userKeys) == 0 {
		return nil
	}
	doc, _ := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []any{map[string]any{
			"Effect":   "Allow",
			"Action":   []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"},
			"Resource": []string{"arn:aws:s3:::" + bucket, "arn:aws:s3:::" + bucket + "/*"},
		}},
	})
	if err := c.PutPolicy(policy, doc); err != nil {
		return fmt.Errorf("bucket policy: %w", err)
	}
	for _, k := range userKeys {
		if err := c.AttachPolicy(k, policy); err != nil && !strings.Contains(strings.ToLower(err.Error()), "already") {
			return fmt.Errorf("give %s access: %w", k, err)
		}
	}
	return nil
}
