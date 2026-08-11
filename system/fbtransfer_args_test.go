package system

import (
	"reflect"
	"strings"
	"testing"
)

// fbtHas reports whether argv contains flag as a whole argument.
func fbtHas(argv []string, flag string) bool {
	for _, a := range argv {
		if a == flag {
			return true
		}
	}
	return false
}

func TestBuildTransferArgsRsyncCopyKeepsExisting(t *testing.T) {
	argv := buildTransferArgs("rsync", "copy",
		[]string{"/mnt/pool/a", "/mnt/pool/b"}, "/mnt/ext/dest", false)

	if argv[0] != "rsync" {
		t.Fatalf("want rsync as argv[0], got %q (%v)", argv[0], argv)
	}
	for _, want := range []string{"-aHAX", "--info=progress2", "--no-inc-recursive", "--ignore-existing"} {
		if !fbtHas(argv, want) {
			t.Errorf("missing %q in %v", want, argv)
		}
	}
	if fbtHas(argv, "--remove-source-files") {
		t.Errorf("copy must not delete sources: %v", argv)
	}
	// Sources and destination follow the -- terminator, destination last with a
	// trailing slash so rsync copies *into* the directory.
	i := -1
	for n, a := range argv {
		if a == "--" {
			i = n
			break
		}
	}
	if i < 0 {
		t.Fatalf("missing -- terminator: %v", argv)
	}
	if got, want := argv[i+1:], []string{"/mnt/pool/a", "/mnt/pool/b", "/mnt/ext/dest/"}; !reflect.DeepEqual(got, want) {
		t.Errorf("operands = %v, want %v", got, want)
	}
}

func TestBuildTransferArgsRsyncCopyOverwriteDropsIgnoreExisting(t *testing.T) {
	argv := buildTransferArgs("rsync", "copy", []string{"/mnt/pool/a"}, "/mnt/ext/dest", true)
	if fbtHas(argv, "--ignore-existing") {
		t.Errorf("overwrite must not pass --ignore-existing: %v", argv)
	}
}

func TestBuildTransferArgsRsyncMoveRemovesSources(t *testing.T) {
	argv := buildTransferArgs("rsync", "move", []string{"/mnt/pool/a"}, "/mnt/ext/dest", false)
	if !fbtHas(argv, "--remove-source-files") {
		t.Errorf("move must pass --remove-source-files: %v", argv)
	}
}

func TestBuildTransferArgsCpCopyMatchesLegacyCommand(t *testing.T) {
	argv := buildTransferArgs("cp", "copy", []string{"/mnt/pool/a"}, "/mnt/ext/dest", false)
	want := []string{"cp", "-a", "-n", "--", "/mnt/pool/a", "/mnt/ext/dest"}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

func TestBuildTransferArgsCpCopyOverwriteUsesForce(t *testing.T) {
	argv := buildTransferArgs("cp", "copy", []string{"/mnt/pool/a"}, "/mnt/ext/dest", true)
	want := []string{"cp", "-a", "-f", "--", "/mnt/pool/a", "/mnt/ext/dest"}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

func TestBuildTransferArgsCpMoveMatchesLegacyCommand(t *testing.T) {
	argv := buildTransferArgs("cp", "move", []string{"/mnt/pool/a"}, "/mnt/ext/dest", false)
	want := []string{"mv", "-n", "--", "/mnt/pool/a", "/mnt/ext/dest"}
	if !reflect.DeepEqual(argv, want) {
		t.Errorf("argv = %v, want %v", argv, want)
	}
}

// A destination that already ends in a slash must not grow a second one —
// rsync treats "//" as a distinct path on some remotes.
func TestBuildTransferArgsRsyncDestinationSlashNotDoubled(t *testing.T) {
	argv := buildTransferArgs("rsync", "copy", []string{"/mnt/pool/a"}, "/mnt/ext/dest/", false)
	last := argv[len(argv)-1]
	if strings.HasSuffix(last, "//") {
		t.Errorf("destination has a doubled slash: %q", last)
	}
	if last != "/mnt/ext/dest/" {
		t.Errorf("destination = %q, want /mnt/ext/dest/", last)
	}
}
