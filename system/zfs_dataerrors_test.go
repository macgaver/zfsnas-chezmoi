package system

import "testing"

// Fixtures are verbatim output from the real incident on 192.168.2.5
// (BIGRAID5, 2026-08-17), which is the only reason we know the three entry
// forms that must be handled.

const statusVerboseFixture = `  pool: BIGRAID5
 state: ONLINE
status: One or more devices has experienced an error resulting in data
	corruption.  Applications may be affected.
action: Restore the file in question if possible.  Otherwise restore the
	entire pool from backup.
   see: https://openzfs.github.io/openzfs-docs/msg/ZFS-8000-8A
  scan: scrub repaired 9.71M in 21:14:51 with 21 errors on Sun Aug  9 21:38:52 2026
config:

	NAME                                      STATE     READ WRITE CKSUM
	BIGRAID5                                  ONLINE       0     0     0
	  raidz1-0                                ONLINE       0     0     0
	    29104dfd-0d90-454c-ab82-a2c430ee05c5  ONLINE       0     0     0

errors: Permanent errors have been detected in the following files:

        /BIGRAID5/360/2026-07/2026-07-15 Vol Vers Roberval gros vent 360/VID_20260715_162122_00_001.insv
        BIGRAID5/360@auto-20260802-020041:/2026-07/2026-07-31 Vol retour de Roberval 360/VID_20181008_115555_00_005.insv
        <0x1a2b>:<0x5c6d>
`

// parseDataErrorFiles must keep every entry verbatim — the paths contain
// spaces, and the snapshot form carries meaning the UI renders differently.
func TestParseDataErrorFiles(t *testing.T) {
	got := parseDataErrorFiles(statusVerboseFixture)
	want := []string{
		"/BIGRAID5/360/2026-07/2026-07-15 Vol Vers Roberval gros vent 360/VID_20260715_162122_00_001.insv",
		"BIGRAID5/360@auto-20260802-020041:/2026-07/2026-07-31 Vol retour de Roberval 360/VID_20181008_115555_00_005.insv",
		"<0x1a2b>:<0x5c6d>",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

// Nothing above the "Permanent errors" header may be mistaken for an entry —
// the config block is indented too.
func TestParseDataErrorFilesIgnoresConfigBlock(t *testing.T) {
	for _, e := range parseDataErrorFiles(statusVerboseFixture) {
		if e == "BIGRAID5" || e == "raidz1-0" ||
			e == "29104dfd-0d90-454c-ab82-a2c430ee05c5  ONLINE       0     0     0" {
			t.Fatalf("config-block line leaked into the file list: %q", e)
		}
	}
}

// A clean pool has no header at all; the result must be empty, never nil-deref.
func TestParseDataErrorFilesClean(t *testing.T) {
	clean := "  pool: tank\n state: ONLINE\n\nerrors: No known data errors\n"
	if got := parseDataErrorFiles(clean); len(got) != 0 {
		t.Errorf("clean pool produced entries: %#v", got)
	}
	if got := parseDataErrorFiles(""); len(got) != 0 {
		t.Errorf("empty input produced entries: %#v", got)
	}
}

// The count lives only in the NON-verbose output: with -v the errors: line is
// replaced by the "Permanent errors…" header and the number disappears.
func TestParseDataErrorCount(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"real incident", "errors: 21 data errors, use '-v' for a list\n", 21},
		{"after replacement", "errors: 18 data errors, use '-v' for a list\n", 18},
		{"single", "errors: 1 data errors, use '-v' for a list\n", 1},
		{"clean", "errors: No known data errors\n", 0},
		{"verbose form carries no count", statusVerboseFixture, 0},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		if got := parseDataErrorCount(tc.in); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

// The count and the resolvable list legitimately disagree: records for deleted
// objects still count but no longer resolve to a name. Reporting that number is
// what turns "two errors with no filename" into an explainable state.
func TestDataErrorUnresolved(t *testing.T) {
	cases := []struct {
		name        string
		count, list int
		want        int
	}{
		{"observed 18 vs 12", 18, 12, 6},
		{"all resolvable", 20, 20, 0},
		{"list longer than count floors at zero", 12, 18, 0},
		{"nothing", 0, 0, 0},
	}
	for _, tc := range cases {
		if got := dataErrorUnresolved(tc.count, tc.list); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

// A pathological pool must not blow up the API payload.
func TestParseDataErrorFilesCaps(t *testing.T) {
	in := "errors: Permanent errors have been detected in the following files:\n\n"
	for i := 0; i < dataErrorFileCap+50; i++ {
		in += "        /tank/file\n"
	}
	if got := parseDataErrorFiles(in); len(got) != dataErrorFileCap {
		t.Errorf("got %d entries, want cap of %d", len(got), dataErrorFileCap)
	}
}
