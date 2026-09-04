// system/appliance_ssh.go
// Appliance SSH unlock: the image ships root locked (passwd -l). Setting a
// password (or key) from the portal is the only way in over SSH. Both writes
// land in persisted paths (etc-auth/shadow, root-ssh/). v6.8.28.
package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	rootSSHDir = "/root/.ssh"
	// chpasswd replaces the hash outright, which also clears the "!" lock
	// prefix passwd -l added at image build — no separate unlock needed.
	chpasswdRun = func(pw string) error {
		cmd := exec.Command("chpasswd")
		cmd.Stdin = strings.NewReader("root:" + pw + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("chpasswd: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)

var sshKeyRe = regexp.MustCompile(
	`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/=]+( [^\r\n]*)?$`)

// SetRootSSHAccess sets the root password and/or appends an SSH public key
// for root. Either argument may be empty; both empty is an error.
func SetRootSSHAccess(password, authorizedKey string) error {
	if password == "" && authorizedKey == "" {
		return fmt.Errorf("nothing to set")
	}
	if password != "" {
		if strings.ContainsAny(password, "\n\r:") {
			return fmt.Errorf("password may not contain newlines or ':'")
		}
		if err := chpasswdRun(password); err != nil {
			return err
		}
		if err := SyncAuthToPersistStore(); err != nil {
			return fmt.Errorf("password set but persist sync failed (will not survive reboot): %w", err)
		}
	}
	if authorizedKey != "" {
		key := strings.TrimSpace(authorizedKey)
		if !sshKeyRe.MatchString(key) {
			return fmt.Errorf("unrecognized SSH public key format")
		}
		if err := os.MkdirAll(rootSSHDir, 0700); err != nil {
			return err
		}
		akPath := filepath.Join(rootSSHDir, "authorized_keys")
		existing, _ := os.ReadFile(akPath)
		for _, l := range strings.Split(string(existing), "\n") {
			if strings.TrimSpace(l) == key {
				return nil // already present
			}
		}
		f, err := os.OpenFile(akPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString(key + "\n"); err != nil {
			return err
		}
	}
	return nil
}
