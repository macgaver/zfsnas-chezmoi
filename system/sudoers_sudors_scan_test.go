package system

import (
	"strings"
	"testing"
)

// splitSudoersCommands renders the template and returns every command entry
// ("/usr/bin/foo -x *") paired with its 1-based line number, unfolding the
// backslash continuations and the comma-separated entries that share a line.
func splitSudoersCommands(t *testing.T) []struct {
	Line int
	Cmd  string
} {
	t.Helper()
	rendered := strings.Replace(requiredSudoersTemplate, "{{ZFSNAS_FILES}}", buildFilesAlias(), 1)
	rendered = strings.Replace(rendered, "{{LXD_CAT_LINE}}", lxdConsoleCatLine(), 1)
	rendered = widenWildcardsForSudoRS(rendered)

	var out []struct {
		Line int
		Cmd  string
	}
	for i, raw := range strings.Split(rendered, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "\\"))
		if strings.HasPrefix(line, "#") {
			continue
		}
		// A Cmnd_Alias header may carry its first command after the '='.
		if strings.HasPrefix(line, "Cmnd_Alias ") {
			if eq := strings.Index(line, "="); eq >= 0 {
				line = strings.TrimSpace(line[eq+1:])
			}
		}
		for _, cmd := range strings.Split(line, ",") {
			cmd = strings.TrimSpace(cmd)
			if !strings.HasPrefix(cmd, "/") {
				continue
			}
			out = append(out, struct {
				Line int
				Cmd  string
			}{i + 1, cmd})
		}
	}
	if len(out) == 0 {
		t.Fatal("no command entries parsed out of the sudoers template")
	}
	return out
}

// sudo-rs (Ubuntu 26.04+) accepts `*` ONLY as an entire trailing argument. Any
// other shape — a prefix ("/tmp/znas-mergerfs/*"), a suffix ("*.mount"), or a
// middle position — is rejected with
//
//	wildcards are not allowed in command arguments
//
// and that single rejection desyncs the parser: every following line of the
// same alias becomes "garbage at end of line", sudo-rs renders the whole alias
// as `???` in `sudo -l`, and all of its grants are silently dropped.
//
// TestSudoRSSubstitutionsRemoveAllWildcardErrors only checks a hand-written
// list of known-bad strings, so it cannot catch a NEW template entry. This test
// scans EVERY entry instead. It is the guard that would have caught the
// ZFSNAS_MERGERFS alias (v6.7.13), which shipped 10 illegal entries and broke
// sudo on every sudo-rs host.
func TestNoWildcardsInSudoersCommandArguments(t *testing.T) {
	for _, e := range splitSudoersCommands(t) {
		toks := strings.Fields(e.Cmd)
		for i, tok := range toks {
			if i == 0 || !strings.Contains(tok, "*") {
				continue // token 0 is the command path; sudo-rs globs those fine
			}
			if tok == "*" && i == len(toks)-1 {
				continue // the one legal shape
			}
			t.Errorf("template line %d: sudo-rs rejects argument %q in %q\n"+
				"  add a widening pair to widenWildcardsForSudoRS (a lone trailing `*`)",
				e.Line, tok, e.Cmd)
		}
	}
}
