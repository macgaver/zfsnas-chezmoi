package system

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"zfsnas/internal/config"
)

// MinIOServiceStatus describes the current state of the MinIO daemon.
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

// MinIOPrereqsInstalled returns true when both the minio and mc binaries are present.
func MinIOPrereqsInstalled() bool {
	return binaryInstalled("minio", "mc")
}

// InstallMinIO downloads the minio and mc binaries, creates the minio-user system
// account, writes the systemd unit file, and enables the service.
// This function is intentionally synchronous (called from an HTTP handler with a
// generous write timeout).
func InstallMinIO() error {
	steps := []struct {
		desc string
		args []string
	}{
		{
			"Downloading minio binary",
			[]string{"wget", "-q", "-O", "/usr/local/bin/minio",
				"https://dl.min.io/server/minio/release/linux-amd64/minio"},
		},
		{
			"Downloading mc client binary",
			[]string{"wget", "-q", "-O", "/usr/local/bin/mc",
				"https://dl.min.io/client/mc/release/linux-amd64/mc"},
		},
		{
			"Setting minio executable",
			[]string{"chmod", "+x", "/usr/local/bin/minio"},
		},
		{
			"Setting mc executable",
			[]string{"chmod", "+x", "/usr/local/bin/mc"},
		},
	}

	for _, s := range steps {
		args := append([]string{s.args[0]}, s.args[1:]...)
		cmd := exec.Command("sudo", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", s.desc, err, strings.TrimSpace(string(out)))
		}
	}

	// Create minio-user system account if it doesn't already exist.
	if out, err := exec.Command("id", "minio-user").CombinedOutput(); err != nil {
		if out2, err2 := exec.Command("sudo", "useradd",
			"--system", "--home-dir", "/var/lib/minio",
			"--shell", "/usr/sbin/nologin", "minio-user").CombinedOutput(); err2 != nil {
			return fmt.Errorf("useradd minio-user: %w: %s", err2, strings.TrimSpace(string(out2)))
		}
	} else {
		_ = out
	}

	// Ensure /var/lib/minio exists and is owned by minio-user.
	for _, cmd := range [][]string{
		{"mkdir", "-p", "/var/lib/minio"},
		{"chown", "minio-user:minio-user", "/var/lib/minio"},
	} {
		if out, err := exec.Command("sudo", cmd...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
	}

	// Write the systemd service unit.
	if err := WriteMinIOServiceUnit(); err != nil {
		return fmt.Errorf("write service unit: %w", err)
	}

	// Reload and enable (but don't start yet — user must configure first).
	for _, args := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "minio"},
	} {
		if out, err := exec.Command("sudo", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

// WriteMinIOServiceUnit writes /etc/systemd/system/minio.service via sudo tee.
func WriteMinIOServiceUnit() error {
	unit := `[Unit]
Description=MinIO Object Storage
Documentation=https://min.io/docs/minio/linux/index.html
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/usr/local/bin/minio

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=-/etc/default/minio
ExecStartPre=/bin/bash -c "if [ -z \"${MINIO_VOLUMES}\" ]; then echo 'MINIO_VOLUMES not set in /etc/default/minio'; exit 1; fi"
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`
	tee := exec.Command("sudo", "tee", "/etc/systemd/system/minio.service")
	tee.Stdin = strings.NewReader(unit)
	if out, err := tee.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WriteMinIOEnvFile writes /etc/default/minio with the given config via sudo tee.
func WriteMinIOEnvFile(cfg *config.MinIOConfig) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "MINIO_ROOT_USER=%s\n", cfg.RootUser)
	fmt.Fprintf(&sb, "MINIO_ROOT_PASSWORD=%s\n", cfg.RootPassword)
	fmt.Fprintf(&sb, "MINIO_VOLUMES=%s\n", cfg.DataDir)
	fmt.Fprintf(&sb, "MINIO_OPTS=\"--address :%d --console-address :%d\"\n", cfg.Port, cfg.ConsolePort)
	fmt.Fprintf(&sb, "MINIO_SITE_REGION=%s\n", cfg.Region)
	if cfg.SiteName != "" {
		fmt.Fprintf(&sb, "MINIO_SITE_NAME=%s\n", cfg.SiteName)
	}
	if cfg.ServerURL != "" {
		fmt.Fprintf(&sb, "MINIO_SERVER_URL=%s\n", cfg.ServerURL)
	}

	tee := exec.Command("sudo", "tee", "/etc/default/minio")
	tee.Stdin = strings.NewReader(sb.String())
	if out, err := tee.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	// Restrict access: root-owned, readable only by root and minio-user (via group).
	exec.Command("sudo", "chown", "root:minio-user", "/etc/default/minio").Run()
	exec.Command("sudo", "chmod", "640", "/etc/default/minio").Run()

	// Ensure DataDir exists and is owned by minio-user.
	if cfg.DataDir != "" {
		for _, args := range [][]string{
			{"mkdir", "-p", cfg.DataDir},
			{"chown", "-R", "minio-user:minio-user", cfg.DataDir},
		} {
			_ = exec.Command("sudo", args...).Run()
		}
	}

	return nil
}

// ApplyMinIOConfig writes the env file, installs/removes TLS certs, restarts the service,
// and refreshes the mc alias. configDir is the portal's config directory (contains certs/).
func ApplyMinIOConfig(cfg *config.MinIOConfig, configDir string) error {
	// Install or remove TLS certs before writing the env file.
	if cfg.TLS {
		if cfg.TLSCertName == "" || cfg.TLSCertName == "auto" {
			if err := EnableMinIOTLS(); err != nil {
				return fmt.Errorf("enable TLS: %w", err)
			}
		} else {
			certFile := filepath.Join(configDir, "certs", cfg.TLSCertName+".crt")
			keyFile := filepath.Join(configDir, "certs", cfg.TLSCertName+".key")
			if err := installMinIOTLSFromFiles(certFile, keyFile); err != nil {
				return fmt.Errorf("install cert %q: %w", cfg.TLSCertName, err)
			}
		}
	} else {
		_ = DisableMinIOTLS()
	}

	if err := WriteMinIOEnvFile(cfg); err != nil {
		return err
	}
	if err := exec.Command("sudo", "systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("daemon-reload: %w", err)
	}
	if err := exec.Command("sudo", "systemctl", "restart", "minio").Run(); err != nil {
		return fmt.Errorf("restart minio: %w", err)
	}
	// Wait for MinIO to become ready (up to 10 s).
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		out, _ := exec.Command("systemctl", "is-active", "minio").Output()
		if strings.TrimSpace(string(out)) == "active" {
			break
		}
	}
	// Set up mc alias so subsequent mc commands work.
	_ = SetupMCAlias(cfg)
	return nil
}

const minIOCertsDir = "/var/lib/minio/.minio/certs"

// EnableMinIOTLS generates a fresh self-signed cert for MinIO (all local IPs included),
// installs it into the MinIO certs directory, and restarts the service.
func EnableMinIOTLS() error {
	// Generate cert in a temp dir, then sudo-copy into place.
	tmp, err := os.MkdirTemp("", "minio-tls-*")
	if err != nil {
		return fmt.Errorf("tmpdir: %w", err)
	}
	defer os.RemoveAll(tmp)

	certFile := filepath.Join(tmp, "public.crt")
	keyFile := filepath.Join(tmp, "private.key")
	if err := generateMinIOCert(certFile, keyFile); err != nil {
		return fmt.Errorf("generate cert: %w", err)
	}

	// Ensure the certs directory exists and is owned by minio-user.
	if out, err := exec.Command("sudo", "mkdir", "-p", minIOCertsDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir certs: %s", strings.TrimSpace(string(out)))
	}
	if err := teeToFixedPath(certFile, filepath.Join(minIOCertsDir, "public.crt")); err != nil {
		return err
	}
	if err := teeToFixedPath(keyFile, filepath.Join(minIOCertsDir, "private.key")); err != nil {
		return err
	}
	if out, err := exec.Command("sudo", "chown", "-R", "minio-user:minio-user", minIOCertsDir).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "640", filepath.Join(minIOCertsDir, "private.key")).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// teeToFixedPath reads src in-process and pipes its contents through sudo tee
// to dst. dst MUST be a fixed string that exactly matches a sudoers entry
// (e.g. "/var/lib/minio/.minio/certs/public.crt"); sudo-rs requires the path
// match the sudoers entry verbatim, with no wildcards.
func teeToFixedPath(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	cmd := exec.Command("sudo", "/usr/bin/tee", dst)
	cmd.Stdin = strings.NewReader(string(data))
	cmd.Stdout = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tee %s: %s", dst, strings.TrimSpace(string(out)))
	}
	return nil
}

// installMinIOTLSFromFiles copies an existing cert/key pair into the MinIO certs directory.
func installMinIOTLSFromFiles(certFile, keyFile string) error {
	if out, err := exec.Command("sudo", "mkdir", "-p", minIOCertsDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir certs: %s", strings.TrimSpace(string(out)))
	}
	if err := teeToFixedPath(certFile, filepath.Join(minIOCertsDir, "public.crt")); err != nil {
		return err
	}
	if err := teeToFixedPath(keyFile, filepath.Join(minIOCertsDir, "private.key")); err != nil {
		return err
	}
	if out, err := exec.Command("sudo", "chown", "-R", "minio-user:minio-user", minIOCertsDir).CombinedOutput(); err != nil {
		return fmt.Errorf("chown: %s", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "640", filepath.Join(minIOCertsDir, "private.key")).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod key: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DisableMinIOTLS removes MinIO cert files so MinIO starts in plain-HTTP mode.
func DisableMinIOTLS() error {
	for _, f := range []string{"public.crt", "private.key"} {
		path := filepath.Join(minIOCertsDir, f)
		exec.Command("sudo", "rm", "-f", path).Run() // ignore errors (file may not exist)
	}
	return nil
}

// generateMinIOCert creates a self-signed ECDSA cert including all local IP addresses.
func generateMinIOCert(certFile, keyFile string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Collect all local unicast IPs to embed as SANs.
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip != nil && !ip.IsLoopback() && (ip.To4() != nil || ip.To16() != nil) {
					ips = append(ips, ip)
				}
			}
		}
	}

	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost", "minio"}
	if hostname != "" {
		dnsNames = append(dnsNames, hostname)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ZFS NAS — MinIO"},
			CommonName:   "minio",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
}

// SetupMCAlias registers the "zfsnas" mc alias pointing at the local MinIO instance.
func SetupMCAlias(cfg *config.MinIOConfig) error {
	scheme := "http"
	if cfg.TLS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d", scheme, cfg.Port)
	args := []string{}
	if cfg.TLS {
		args = append(args, "--insecure")
	}
	args = append(args, "alias", "set", "zfsnas", url, cfg.RootUser, cfg.RootPassword)
	out, err := exec.Command("mc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// UninstallMinIO stops the MinIO service, disables it, removes the binaries,
// and cleans up the systemd unit and env file.
func UninstallMinIO() error {
	exec.Command("sudo", "systemctl", "stop", "minio").Run()
	exec.Command("sudo", "systemctl", "disable", "minio").Run()
	for _, f := range []string{
		"/usr/local/bin/minio",
		"/usr/local/bin/mc",
		"/etc/systemd/system/minio.service",
		"/etc/default/minio",
	} {
		exec.Command("sudo", "rm", "-f", f).Run()
	}
	exec.Command("sudo", "systemctl", "daemon-reload").Run()
	// Drop the removed binaries from the sticky presence cache so
	// MinIOPrereqsInstalled() reports false without a service restart.
	ForgetBinaryPresence("minio")
	ForgetBinaryPresence("mc")
	return nil
}

// GetMinIOServiceStatus returns whether the MinIO systemd service is active.
func GetMinIOServiceStatus() MinIOServiceStatus {
	out, err := exec.Command("systemctl", "is-active", "minio").Output()
	status := strings.TrimSpace(string(out))
	if err != nil && status == "" {
		status = "inactive"
	}
	return MinIOServiceStatus{Active: status == "active", Status: status}
}

// StartMinIOService starts the MinIO service.
func StartMinIOService() error {
	out, err := exec.Command("sudo", "systemctl", "start", "minio").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StopMinIOService stops the MinIO service.
func StopMinIOService() error {
	out, err := exec.Command("sudo", "systemctl", "stop", "minio").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RestartMinIOService restarts the MinIO service.
func RestartMinIOService() error {
	out, err := exec.Command("sudo", "systemctl", "restart", "minio").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── S3 User Management ────────────────────────────────────────────────────────

// ListS3Users returns all MinIO IAM users by running mc admin user list --json.
func ListS3Users() ([]S3UserInfo, error) {
	out, err := exec.Command("mc", "admin", "user", "list", "--json", "zfsnas").Output()
	if err != nil {
		return nil, fmt.Errorf("mc admin user list: %w", err)
	}
	var users []S3UserInfo
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw struct {
			AccessKey  string `json:"accessKey"`
			UserStatus string `json:"userStatus"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		status := raw.UserStatus
		if status == "" {
			status = "enabled"
		}
		users = append(users, S3UserInfo{
			AccessKey: raw.AccessKey,
			Status:    status,
		})
	}
	if users == nil {
		users = []S3UserInfo{}
	}
	return users, nil
}

// CreateS3User creates a new MinIO IAM user.
func CreateS3User(accessKey, secretKey string) error {
	out, err := exec.Command("mc", "admin", "user", "add", "zfsnas", accessKey, secretKey).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// DeleteS3User removes a MinIO IAM user.
func DeleteS3User(accessKey string) error {
	out, err := exec.Command("mc", "admin", "user", "remove", "zfsnas", accessKey).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetS3UserStatus enables or disables a MinIO IAM user.
func SetS3UserStatus(accessKey string, enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	out, err := exec.Command("mc", "admin", "user", action, "zfsnas", accessKey).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetS3UserPassword updates a MinIO IAM user's secret key (mc upserts on add).
func SetS3UserPassword(accessKey, newSecret string) error {
	out, err := exec.Command("mc", "admin", "user", "add", "zfsnas", accessKey, newSecret).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── S3 Bucket Management ──────────────────────────────────────────────────────

// CreateS3Bucket creates a bucket in MinIO with the given options.
func CreateS3Bucket(opts S3BucketCreateOptions) error {
	target := "zfsnas/" + opts.Name

	// Create the bucket (with object lock if requested — implies versioning).
	var args []string
	if opts.ObjectLock {
		args = []string{"mc", "mb", "--with-lock", target}
	} else {
		args = []string{"mc", "mb", target}
	}
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("mc mb: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Set versioning (object lock already enables it).
	if !opts.ObjectLock && opts.Versioning != "" && opts.Versioning != "off" {
		vCmd := "enable"
		if opts.Versioning == "suspended" {
			vCmd = "suspend"
		}
		if out, err := exec.Command("mc", "version", vCmd, target).CombinedOutput(); err != nil {
			return fmt.Errorf("mc version %s: %w: %s", vCmd, err, strings.TrimSpace(string(out)))
		}
	}

	// Set quota if specified.
	if opts.Quota != "" && opts.Quota != "0" {
		if out, err := exec.Command("mc", "quota", "set", target, "--size", opts.Quota).CombinedOutput(); err != nil {
			return fmt.Errorf("mc quota set: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	// Set anonymous access policy.
	if opts.AnonAccess == "download" || opts.AnonAccess == "public" {
		policy := opts.AnonAccess
		if out, err := exec.Command("mc", "anonymous", "set", policy, target).CombinedOutput(); err != nil {
			return fmt.Errorf("mc anonymous set: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

// DeleteS3Bucket removes a bucket and all its objects.
func DeleteS3Bucket(name string) error {
	target := "zfsnas/" + name
	out, err := exec.Command("mc", "rb", "--force", "--dangerous", target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// S3ApplyVersioning sets the versioning state on an existing bucket.
func S3ApplyVersioning(target, versioning string) error {
	switch versioning {
	case "enabled":
		out, err := exec.Command("mc", "version", "enable", target).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
	case "suspended":
		out, err := exec.Command("mc", "version", "suspend", target).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// S3ApplyQuota sets or clears the bucket quota.
func S3ApplyQuota(target, quota string) error {
	if quota == "" || quota == "0" {
		exec.Command("mc", "quota", "clear", target).Run()
		return nil
	}
	out, err := exec.Command("mc", "quota", "set", target, "--size", quota).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// S3ApplyAnonAccess sets the anonymous access policy on a bucket.
func S3ApplyAnonAccess(target, anonAccess string) error {
	policy := anonAccess
	if policy == "" || policy == "none" {
		policy = "none"
	}
	out, err := exec.Command("mc", "anonymous", "set", policy, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyBucketUserPolicy creates or updates the per-bucket IAM policy and assigns it to users.
// userKeys is the new desired set of users with access. prevKeys is the previous set (to detach).
func ApplyBucketUserPolicy(bucketName string, userKeys, prevKeys []string) error {
	policyName := "zfsnas-" + bucketName

	if len(userKeys) == 0 && len(prevKeys) == 0 {
		return nil
	}

	// Build the set of keys to remove (were in prev, not in new).
	newSet := make(map[string]bool, len(userKeys))
	for _, k := range userKeys {
		newSet[k] = true
	}
	for _, k := range prevKeys {
		if !newSet[k] {
			// Detach (ignore error — user may already not have the policy).
			_ = exec.Command("mc", "admin", "policy", "detach", "zfsnas", policyName, "--user", k).Run()
		}
	}

	if len(userKeys) == 0 {
		return nil
	}

	// Write the bucket-scoped read/write IAM policy to a temp file.
	policyJSON := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Resource": [
        "arn:aws:s3:::%s",
        "arn:aws:s3:::%s/*"
      ]
    }
  ]
}`, bucketName, bucketName)

	tmpFile := filepath.Join(os.TempDir(), "zfsnas-policy-"+bucketName+".json")
	if err := os.WriteFile(tmpFile, []byte(policyJSON), 0600); err != nil {
		return fmt.Errorf("write policy file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Create or update the policy in MinIO.
	if out, err := exec.Command("mc", "admin", "policy", "create", "zfsnas", policyName, tmpFile).CombinedOutput(); err != nil {
		return fmt.Errorf("mc admin policy create: %w: %s", err, strings.TrimSpace(string(out)))
	}

	// Attach the policy to each user in the new set.
	for _, k := range userKeys {
		if out, err := exec.Command("mc", "admin", "policy", "attach", "zfsnas", policyName, "--user", k).CombinedOutput(); err != nil {
			// Ignore "already attached" errors.
			if !strings.Contains(string(out), "already") {
				return fmt.Errorf("mc admin policy attach %s: %w: %s", k, err, strings.TrimSpace(string(out)))
			}
		}
	}

	return nil
}
