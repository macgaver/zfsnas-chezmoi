package system

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// validUnixName is deliberately stricter than useradd's own rules: portal
// usernames become real system accounts here, so anything that could be
// mistaken for a flag, a path, or a second field is rejected outright.
var validUnixName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// EnsureShellUser creates (or updates) a Linux account that can log in over
// SSH, and sets its password.
//
// This is what the portal's "Allow SSH login" checkbox drives. It is separate
// from EnsureSambaUser, which deliberately creates a NO-login account for file
// sharing — an SMB user must not get a shell as a side effect.
func EnsureShellUser(username, password string) error {
	if !validUnixName.MatchString(username) {
		return fmt.Errorf("%q is not a valid system user name (lowercase letters, digits, - and _, starting with a letter or _)", username)
	}
	if password == "" {
		return fmt.Errorf("a password is required to enable SSH login")
	}
	// chpasswd reads "user:password" from stdin, one per line — a newline or
	// colon in the password would inject a second instruction.
	if strings.ContainsAny(password, "\n\r:") {
		return fmt.Errorf("password may not contain newlines or ':'")
	}

	if err := exec.Command("id", username).Run(); err != nil {
		out, err2 := exec.Command("sudo", "useradd", "-m", "-s", "/bin/bash", username).CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("useradd %s: %s", username, strings.TrimSpace(string(out)))
		}
	} else {
		// Existing account (e.g. one created earlier for SMB, which has no
		// shell): give it one, otherwise SSH would authenticate and hang up.
		if out, err := exec.Command("sudo", "usermod", "-s", "/bin/bash", username).CombinedOutput(); err != nil {
			return fmt.Errorf("usermod %s: %s", username, strings.TrimSpace(string(out)))
		}
	}

	cmd := exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("set password for %s: %s", username, strings.TrimSpace(string(out)))
	}

	// On the appliance /etc/passwd & shadow are restored from the persist store
	// at boot, so an account created here would vanish on the next reboot
	// unless it is copied back out now. No-op off-appliance.
	if err := SyncAuthToPersistStore(); err != nil {
		return fmt.Errorf("account created but persisting it failed (it would not survive a reboot): %w", err)
	}
	return nil
}

// sudoGroup is the group whose members may run sudo. Debian and Ubuntu ship
// /etc/sudoers with "%sudo ALL=(ALL:ALL) ALL", and the portal's sudoers
// hardening only ever writes /etc/sudoers.d/zfsnas, so that line survives
// hardening untouched. Membership is therefore exactly what lets an operator
// run `sudo -s` and be prompted for THEIR OWN password. Deliberately no
// NOPASSWD anywhere here: the prompt is the point.
const sudoGroup = "sudo"

// groupFilePath is a var so tests can point it at a fixture.
var groupFilePath = "/etc/group"

// groupMembers returns the supplementary members of a group as listed in the
// /etc/group line's fourth field.
func groupMembers(path, group string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] != group {
			continue
		}
		var out []string
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// InSudoGroup reports whether the account is a member of the sudo group.
func InSudoGroup(username string) bool {
	if !validUnixName.MatchString(username) {
		return false
	}
	for _, m := range groupMembers(groupFilePath, sudoGroup) {
		if m == username {
			return true
		}
	}
	return false
}

// EnsureSudoAccess puts an account in the sudo group so an admin who signs in
// over SSH can `sudo -s` to root, authenticating with their own password.
//
// gpasswd, not `usermod -aG`: the hardened sudoers allowlist grants
// /usr/bin/gpasswd * for group management but restricts usermod to
// "-aG sambashare *", so a usermod call here would be refused outright on a
// hardened host — silently leaving the admin without root.
func EnsureSudoAccess(username string) error {
	if !validUnixName.MatchString(username) {
		return fmt.Errorf("invalid system user name %q", username)
	}
	if exec.Command("id", username).Run() != nil {
		return fmt.Errorf("no system account exists for %q", username)
	}
	if InSudoGroup(username) {
		return nil // already a member; nothing to write or persist
	}
	if out, err := exec.Command("sudo", "gpasswd", "-a", username, sudoGroup).CombinedOutput(); err != nil {
		return fmt.Errorf("add %s to the %s group: %s", username, sudoGroup, strings.TrimSpace(string(out)))
	}
	// /etc/group and /etc/gshadow are copy-type manifest entries on the
	// appliance: without this the membership is gone after a reboot.
	return SyncAuthToPersistStore()
}

// RemoveSudoAccess takes sudo away again — used when an admin loses SSH access
// or is demoted, so a former admin is never left holding root.
func RemoveSudoAccess(username string) error {
	if !validUnixName.MatchString(username) {
		return fmt.Errorf("invalid system user name %q", username)
	}
	if exec.Command("id", username).Run() != nil {
		return nil // no account: nothing to take away
	}
	if !InSudoGroup(username) {
		return nil
	}
	if out, err := exec.Command("sudo", "gpasswd", "-d", username, sudoGroup).CombinedOutput(); err != nil {
		return fmt.Errorf("remove %s from the %s group: %s", username, sudoGroup, strings.TrimSpace(string(out)))
	}
	return SyncAuthToPersistStore()
}

// SyncSudoAccess reconciles sudo-group membership with the one rule the portal
// applies: an ADMIN who can log in over SSH gets it, everyone else does not.
// Calling this after any role or SSH change keeps a demoted account, or one
// whose SSH was switched off, from quietly retaining root.
func SyncSudoAccess(username string, isAdmin bool) error {
	if isAdmin && ShellLoginEnabled(username) {
		return EnsureSudoAccess(username)
	}
	return RemoveSudoAccess(username)
}

// ShellLoginEnabled reports whether an account can log in over SSH, judged by
// the shell recorded in /etc/passwd — which is exactly what EnsureShellUser
// and DisableShellLogin flip. The lock flag in /etc/shadow is deliberately not
// consulted: that file is root-only, and off-appliance the portal runs as an
// unprivileged service user, so reading it would fail and every user would
// look disabled.
func ShellLoginEnabled(username string) bool {
	if !validUnixName.MatchString(username) {
		return false
	}
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] != username {
			continue
		}
		switch shell := strings.TrimSpace(f[6]); shell {
		case "", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
			return false
		default:
			return true
		}
	}
	return false
}

// DisableShellLogin takes SSH access away again without deleting the account
// (it may still be a Samba user): the shell becomes nologin and the password
// is locked.
func DisableShellLogin(username string) error {
	if !validUnixName.MatchString(username) {
		return fmt.Errorf("invalid system user name %q", username)
	}
	if err := exec.Command("id", username).Run(); err != nil {
		return nil // no such account: nothing to disable
	}
	if out, err := exec.Command("sudo", "usermod", "-s", "/usr/sbin/nologin", "-L", username).CombinedOutput(); err != nil {
		return fmt.Errorf("usermod %s: %s", username, strings.TrimSpace(string(out)))
	}
	return SyncAuthToPersistStore()
}
