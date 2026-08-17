package system

import (
	"strings"
	"testing"
)

// Keeping an "extra" line used to corrupt the sudoers file.
//
// The ZFSNAS_EXTRA alias was added to the grant with
// strings.Replace(content, "ZFSNAS_SECURITY", "ZFSNAS_SECURITY, ZFSNAS_EXTRA", 1).
// ZFSNAS_SECURITY's FIRST occurrence in the template is its own Cmnd_Alias
// DEFINITION, which sits above the grant line — so the replacement produced
//
//	Cmnd_Alias ZFSNAS_SECURITY, ZFSNAS_EXTRA = \
//
// which classic sudo rejects outright:
//
//	/etc/sudoers.d/zfsnas:287:27: syntax error
//
// A rejected file grants NOTHING, so every portal privilege silently died, and
// every sudo call on the host started printing a parse warning.
func TestSilencedExtraDoesNotCorruptAliasDefinition(t *testing.T) {
	content := BuildSudoersContent(RequiredSudoersContent(), nil,
		[]string{"/usr/bin/custom-tool"})

	if strings.Contains(content, "Cmnd_Alias ZFSNAS_SECURITY, ZFSNAS_EXTRA") {
		t.Error("the ZFSNAS_SECURITY alias DEFINITION was rewritten — sudo will reject the file")
	}
	if !strings.Contains(content, "Cmnd_Alias ZFSNAS_SECURITY = ") {
		t.Error("the ZFSNAS_SECURITY alias definition is no longer intact")
	}
}

// Every Cmnd_Alias declaration must name exactly one alias before '='.
// This is the property sudo's grammar enforces and the bug violated.
func TestCmndAliasDeclarationsAreWellFormed(t *testing.T) {
	for _, extras := range [][]string{
		nil,
		{"/usr/bin/custom-tool"},
		{"/usr/bin/custom-tool", "/usr/local/bin/site-script"},
	} {
		content := BuildSudoersContent(RequiredSudoersContent(), nil, extras)
		for i, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "Cmnd_Alias ") {
				continue
			}
			decl := strings.TrimPrefix(trimmed, "Cmnd_Alias ")
			eq := strings.Index(decl, "=")
			if eq < 0 {
				continue
			}
			name := strings.TrimSpace(decl[:eq])
			if strings.ContainsAny(name, ", \t") {
				t.Errorf("extras=%v: malformed Cmnd_Alias at line %d — alias name %q must be a single identifier:\n  %s",
					extras, i+1, name, line)
			}
		}
	}
}

// The preserved commands are useless unless the grant actually references the
// alias, so the grant line must gain ZFSNAS_EXTRA exactly once.
func TestSilencedExtraIsGranted(t *testing.T) {
	content := BuildSudoersContent(RequiredSudoersContent(), nil,
		[]string{"/usr/bin/custom-tool"})

	if n := strings.Count(content, "Cmnd_Alias ZFSNAS_EXTRA = "); n != 1 {
		t.Errorf("want exactly 1 ZFSNAS_EXTRA definition, got %d", n)
	}

	var grant string
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.Contains(l, "NOPASSWD:") {
			grant = l
			for j := i; j < len(lines) && strings.HasSuffix(strings.TrimRight(lines[j], " "), "\\"); j++ {
				grant += "\n" + lines[j+1]
			}
			break
		}
	}
	if grant == "" {
		t.Fatal("no grant line found")
	}
	if !strings.Contains(grant, "ZFSNAS_EXTRA") {
		t.Errorf("grant line does not reference ZFSNAS_EXTRA — preserved commands are not granted:\n%s", grant)
	}
	if !strings.Contains(grant, "ZFSNAS_SECURITY") {
		t.Errorf("grant line lost ZFSNAS_SECURITY:\n%s", grant)
	}
}

// No extras kept → the file must be byte-identical to the template.
func TestNoExtrasLeavesTemplateUntouched(t *testing.T) {
	req := RequiredSudoersContent()
	if got := BuildSudoersContent(req, nil, nil); got != req {
		t.Error("BuildSudoersContent altered the template when nothing was silenced")
	}
}
