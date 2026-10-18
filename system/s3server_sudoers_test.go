package system

import (
	"strings"
	"testing"
)

// sudoersAllows reports whether a Cmnd_Alias line of the template permits cmd:
// an exact match, or a trailing " *" wildcard (the only shape the hardened
// template uses). "\:" in the template is a literal ":".
func sudoersAllows(template, cmd string) bool {
	for _, raw := range strings.Split(template, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Cmnd_Alias") {
			continue
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\\"), " ")
		line = strings.TrimSuffix(line, ",")
		line = strings.ReplaceAll(line, `\:`, ":")
		if line == cmd {
			return true
		}
		if strings.HasSuffix(line, " *") && strings.HasPrefix(cmd, strings.TrimSuffix(line, "*")) {
			return true
		}
	}
	return false
}

// Every command the RustFS code runs through sudo, as it runs it for a
// dataset mounted at /mnt/tank/s3, must be in the hardened allow-list —
// otherwise the S3 feature breaks on hardened hosts with a sudo password
// prompt (no TTY) instead of an explanation.
func TestRustFSSudoCommandsAreAllowed(t *testing.T) {
	tpl := RequiredSudoersContent()
	cmds := []string{
		// install
		"/usr/bin/tee /usr/local/bin/rustfs",
		"/usr/bin/chmod 755 /usr/local/bin/rustfs",
		// EnsureS3Service
		"/usr/sbin/useradd --system --home-dir /var/lib/rustfs --shell /usr/sbin/nologin rustfs",
		"/usr/bin/mkdir -p /var/lib/rustfs/tls",
		"/usr/bin/chown -R rustfs:rustfs /var/lib/rustfs",
		"/usr/bin/tee /etc/systemd/system/rustfs.service",
		"/usr/bin/systemctl daemon-reload",
		"/usr/bin/systemctl enable rustfs",
		// ApplyS3Config
		"/usr/bin/tee /var/lib/rustfs/tls/rustfs_cert.pem",
		"/usr/bin/tee /var/lib/rustfs/tls/rustfs_key.pem",
		"/usr/bin/chmod 640 /var/lib/rustfs/tls/rustfs_key.pem",
		"/usr/bin/rm -f /var/lib/rustfs/tls/rustfs_cert.pem",
		"/usr/bin/rm -f /var/lib/rustfs/tls/rustfs_key.pem",
		"/usr/bin/mkdir -p /mnt/tank/s3/rustfs-data",
		"/usr/bin/chown -R rustfs:rustfs /mnt/tank/s3/rustfs-data",
		"/usr/bin/tee /etc/default/rustfs",
		"/usr/bin/chown root:rustfs /etc/default/rustfs",
		"/usr/bin/chmod 640 /etc/default/rustfs",
		"/usr/bin/systemctl stop minio",
		"/usr/bin/systemctl disable minio",
		"/usr/bin/systemctl restart rustfs",
		// service actions
		"/usr/bin/systemctl start rustfs",
		"/usr/bin/systemctl stop rustfs",
		// startup re-apply
		"/usr/sbin/zfs get -H -o value mounted tank/s3",
		// uninstall
		"/usr/bin/systemctl disable rustfs",
		"/usr/bin/rm -f /usr/local/bin/rustfs",
		"/usr/bin/rm -f /etc/systemd/system/rustfs.service",
		"/usr/bin/rm -f /etc/default/rustfs",
	}
	for _, c := range cmds {
		if !sudoersAllows(tpl, c) {
			t.Errorf("not in the hardened sudoers template: %s", c)
		}
	}
	if sudoersAllows(tpl, "/usr/bin/wget -q -O /usr/local/bin/minio https://dl.min.io/server/minio/release/linux-amd64/minio") {
		t.Error("the MinIO download rule should be gone")
	}
}
