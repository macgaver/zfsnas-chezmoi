package system

import (
	"regexp"
	"strings"
	"testing"
)

// Every Cmnd_Alias defined in the sudoers template must actually appear in the
// trailing `zfsnas ALL=(ALL) NOPASSWD:` User_Spec grant line — otherwise the
// alias is dead weight and, on a hardened host (specific-alias grant rather
// than blanket NOPASSWD: ALL), the commands it names are silently denied. This
// caught ZFSNAS_SYNCOID, which was defined + experimental-gated but never
// granted, so backup/restore snapshot-mount and `incus admin recover` failed on
// hardened hosts (v6.7.8 fix).
func TestEveryDefinedAliasIsGranted(t *testing.T) {
	content := RequiredSudoersContent()

	// Collect defined alias names.
	defRe := regexp.MustCompile(`(?m)^\s*Cmnd_Alias\s+([A-Z0-9_]+)\s*=`)
	defined := map[string]bool{}
	for _, m := range defRe.FindAllStringSubmatch(content, -1) {
		defined[m[1]] = true
	}
	if len(defined) == 0 {
		t.Fatal("no Cmnd_Alias definitions found — template shape changed?")
	}

	// Extract the granted alias list: the User_Spec line plus any
	// backslash-continuation lines that follow it.
	lines := strings.Split(content, "\n")
	var granted strings.Builder
	inSpec := false
	for _, ln := range lines {
		if !inSpec && strings.HasPrefix(strings.TrimSpace(ln), "zfsnas ") && strings.Contains(ln, "NOPASSWD:") {
			inSpec = true
			granted.WriteString(ln)
			granted.WriteString(" ")
			if !strings.HasSuffix(strings.TrimRight(ln, " "), `\`) {
				break
			}
			continue
		}
		if inSpec {
			granted.WriteString(ln)
			granted.WriteString(" ")
			if !strings.HasSuffix(strings.TrimRight(ln, " "), `\`) {
				break
			}
		}
	}
	grantedTokens := map[string]bool{}
	for _, tok := range regexp.MustCompile(`[A-Z0-9_]+`).FindAllString(granted.String(), -1) {
		grantedTokens[tok] = true
	}

	for name := range defined {
		if !grantedTokens[name] {
			t.Errorf("Cmnd_Alias %s is defined but not present in the User_Spec grant line", name)
		}
	}
}
