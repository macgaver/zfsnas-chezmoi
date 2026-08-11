package system

import (
	"strings"
	"testing"
)

// The File Browser transfer jobs run rsync for progress-reporting copy/move and
// need to kill the process group when the user cancels. Both must be in
// ZFSNAS_FILES — the alias the File Browser's own permission grant covers — not
// only in the optional ZFSNAS_RSYNC alias, which a host without the external
// storage feature never receives.
func TestFilesAliasGrantsTransferCommands(t *testing.T) {
	alias := buildFilesAlias()
	for _, want := range []string{"/usr/bin/rsync *", "/usr/bin/kill *"} {
		if !strings.Contains(alias, want) {
			t.Errorf("ZFSNAS_FILES alias missing %q:\n%s", want, alias)
		}
	}
}

// The Security screen renders each granted command with an explanation of why
// it is needed; a command with no entry shows up there as an unexplained root
// grant. Scoped to the two commands this feature adds — several older
// ZFSNAS_FILES entries predate this invariant and are missing explanations too,
// which is a separate cleanup.
// Both commands already had explanations written for the external-storage
// feature. Those explanations must now also account for the File Browser, or
// the Security screen tells a user who has never enabled external storage that
// rsync is there for a feature they do not use.
func TestTransferSudoersCommandsAreExplained(t *testing.T) {
	for _, cmd := range []string{"/usr/bin/rsync *", "/usr/bin/kill *"} {
		exp, ok := sudoersExplanations[cmd]
		if !ok {
			t.Errorf("no entry in sudoersExplanations for %q", cmd)
			continue
		}
		if !strings.Contains(exp, "File Browser") {
			t.Errorf("explanation for %q does not mention the File Browser: %q", cmd, exp)
		}
	}
}
