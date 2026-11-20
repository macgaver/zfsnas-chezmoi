package system

import (
	"reflect"
	"strings"
	"testing"
)

// zfs get -H -r -o name,property,value,source output of a pool imported
// from TrueNAS: nfsv4 + restricted on the root, a child that inherits it,
// a child with its own posix setting, an Incus storage subtree.
const aclTreeOut = "" +
	"pool\tacltype\tnfsv4\tlocal\n" +
	"pool\taclmode\trestricted\tlocal\n" +
	"pool\taclinherit\tpassthrough\tlocal\n" +
	"pool\txattr\tsa\tlocal\n" +
	"pool\tmountpoint\t/mnt/pool\tdefault\n" +
	"pool/media\tacltype\tnfsv4\tinherited from pool\n" +
	"pool/media\taclmode\trestricted\tinherited from pool\n" +
	"pool/media\taclinherit\tpassthrough\tinherited from pool\n" +
	"pool/media\txattr\tsa\tinherited from pool\n" +
	"pool/media\tmountpoint\t/mnt/pool/media\tdefault\n" +
	"pool/media/tv\tacltype\tnfsv4\tinherited from pool\n" +
	"pool/media/tv\taclmode\trestricted\tinherited from pool\n" +
	"pool/media/tv\taclinherit\tpassthrough\tinherited from pool\n" +
	"pool/media/tv\txattr\tsa\tinherited from pool\n" +
	"pool/media/tv\tmountpoint\t/mnt/pool/media/tv\tdefault\n" +
	"pool/vm\tacltype\tposix\tlocal\n" +
	"pool/vm\taclmode\trestricted\tinherited from pool\n" +
	"pool/vm\taclinherit\tpassthrough\tinherited from pool\n" +
	"pool/vm\txattr\tsa\tinherited from pool\n" +
	"pool/vm\tmountpoint\t/mnt/pool/vm\tdefault\n" +
	"pool/incus\tacltype\tposix\tlocal\n" +
	"pool/incus\taclmode\trestricted\tinherited from pool\n" +
	"pool/incus\taclinherit\tpassthrough\tinherited from pool\n" +
	"pool/incus\txattr\ton\tlocal\n" +
	"pool/incus\tmountpoint\tlegacy\tlocal\n" +
	"pool/incus/containers\tacltype\tposix\tinherited from pool/incus\n" +
	"pool/incus/containers\taclmode\trestricted\tinherited from pool\n" +
	"pool/incus/containers\taclinherit\tpassthrough\tinherited from pool\n" +
	"pool/incus/containers\txattr\ton\tinherited from pool/incus\n" +
	"pool/incus/containers\tmountpoint\tlegacy\tinherited from pool/incus\n"

func TestParseACLTree(t *testing.T) {
	tr := parseACLTree(aclTreeOut, nil)
	if len(tr) != 6 {
		t.Fatalf("got %d datasets", len(tr))
	}
	if tr[0].Preset != PresetNFSv4 || tr[3].Preset != PresetPOSIX {
		t.Fatalf("presets %s %s", tr[0].Preset, tr[3].Preset)
	}
	if p := tr[1].Props["acltype"]; p.Source != "inherited" || p.From != "pool" {
		t.Fatalf("source %+v", p)
	}
	if tr[4].Skip == "" || tr[5].Skip == "" {
		t.Fatalf("incus subtree must be skipped: %+v %+v", tr[4], tr[5])
	}
}

func TestPlanACLChangeOnlyThisDatasetPinsInheritingChildren(t *testing.T) {
	tr := parseACLTree(aclTreeOut, nil)
	ch, err := PlanACLChange(tr, PresetPOSIX, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Follow) != 0 {
		t.Fatalf("follow %v", ch.Follow)
	}
	// media inherits all four from pool → pinned; tv inherits through media → nothing.
	if !reflect.DeepEqual(ch.Pin["pool/media"], map[string]string{"acltype": "nfsv4", "aclmode": "restricted", "aclinherit": "passthrough", "xattr": "sa"}) {
		t.Fatalf("media pin %v", ch.Pin["pool/media"])
	}
	if ch.Pin["pool/media/tv"] != nil {
		t.Fatalf("tv must inherit through the pinned media: %v", ch.Pin["pool/media/tv"])
	}
	// vm has local acltype; only its inherited aclmode/aclinherit/xattr are pinned.
	if _, ok := ch.Pin["pool/vm"]["acltype"]; ok || ch.Pin["pool/vm"]["aclmode"] != "restricted" {
		t.Fatalf("vm pin %v", ch.Pin["pool/vm"])
	}
	// incus has local acltype+xattr; its inherited aclmode/aclinherit are pinned
	// so the change cannot reach Incus storage; containers then inherit from incus.
	if ch.Pin["pool/incus"]["aclmode"] != "restricted" || ch.Pin["pool/incus"]["acltype"] != "" {
		t.Fatalf("incus pin %v", ch.Pin["pool/incus"])
	}
	if ch.Pin["pool/incus/containers"] != nil {
		t.Fatalf("containers pin %v", ch.Pin["pool/incus/containers"])
	}
}

func TestPlanACLChangeRecursiveFollowsButProtects(t *testing.T) {
	tr := parseACLTree(aclTreeOut, nil)
	protect := func(d DatasetACL) string {
		if d.Name == "pool/media" {
			return "SMB share with Windows ACL"
		}
		return ""
	}
	ch, err := PlanACLChange(tr, PresetPOSIX, true, protect)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ch.Follow, []string{"pool/vm"}) {
		t.Fatalf("follow %v", ch.Follow)
	}
	if ch.Skipped["pool/media"] == "" || !strings.HasPrefix(ch.Skipped["pool/media/tv"], "inside pool/media") {
		t.Fatalf("skipped %v", ch.Skipped)
	}
	if ch.Pin["pool/media"]["acltype"] != "nfsv4" || ch.Pin["pool/vm"] != nil {
		t.Fatalf("pin %v", ch.Pin)
	}
	if ch.Skipped["pool/incus"] == "" || ch.Pin["pool/incus"]["aclmode"] != "restricted" {
		t.Fatalf("incus must be kept and pinned: %v %v", ch.Skipped, ch.Pin["pool/incus"])
	}
}

func TestPlanACLChangeChildInheritingFromBelowRootIsUntouched(t *testing.T) {
	tr := parseACLTree(aclTreeOut, nil)
	// Resetting pool/incus itself to inherit (non recursive): containers
	// inherits acltype/xattr from pool/incus, so those are pinned to keep it
	// as it is.
	ch, err := PlanACLChange(tr[4:], PresetInherit, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Pin["pool/incus/containers"]["acltype"] != "posix" || ch.Pin["pool/incus/containers"]["xattr"] != "on" {
		t.Fatalf("pin %v", ch.Pin)
	}
}

func TestPlanACLChangeUnknownPreset(t *testing.T) {
	if _, err := PlanACLChange(parseACLTree(aclTreeOut, nil), "zfs set evil=1", false, nil); err == nil {
		t.Fatal("unknown preset accepted")
	}
}

func TestACLIssues(t *testing.T) {
	tr := parseACLTree(aclTreeOut, nil)
	codes := func(is []ACLIssue) []string {
		var c []string
		for _, i := range is {
			c = append(c, i.Code)
		}
		return c
	}
	// Imported TrueNAS root, no shares: nfsv4 unused + restricted.
	is := ACLIssues(tr[0], nil)
	if !reflect.DeepEqual(codes(is), []string{"nfsv4-unused", "aclmode-restricted"}) || SuggestedPreset(is) != PresetPOSIX {
		t.Fatalf("root %v", codes(is))
	}
	// Same dataset behind a Windows ACL share: only restricted, fixed by nfsv4.
	is = ACLIssues(tr[0], []ACLShareRef{{Kind: "smb", Name: "media", WindowsACL: true}})
	if !reflect.DeepEqual(codes(is), []string{"aclmode-restricted"}) || SuggestedPreset(is) != PresetNFSv4 {
		t.Fatalf("win %v", codes(is))
	}
	// VirtIO-FS on nfsv4 is an error and wins the conflict with a Windows ACL share.
	is = ACLIssues(tr[0], []ACLShareRef{{Kind: "smb", Name: "m", WindowsACL: true}, {Kind: "virtiofs", Name: "vm1"}})
	if is[0].Code != "virtiofs-needs-posix" || is[0].Level != "error" || SuggestedPreset(is) != PresetPOSIX {
		t.Fatalf("vfs %+v", is)
	}
	// Plain posix dataset with sa: nothing.
	if is := ACLIssues(tr[3], []ACLShareRef{{Kind: "virtiofs", Name: "vm1"}, {Kind: "nfs", Name: "/x"}}); len(is) != 0 {
		t.Fatalf("posix %v", codes(is))
	}
	// Portal default (off, xattr=on) with a plain SMB share: nothing to report.
	def := DatasetACL{Props: map[string]ACLProp{"acltype": {Value: "off"}, "xattr": {Value: "on"}, "aclmode": {Value: "discard"}}}
	if is := ACLIssues(def, []ACLShareRef{{Kind: "smb", Name: "s"}}); len(is) != 0 {
		t.Fatalf("default %v", codes(is))
	}
	// posix with xattr=dir: info only, suggestion empty. "on" (= sa on ZFS 2.2+) is not flagged.
	if is := ACLIssues(DatasetACL{Props: map[string]ACLProp{"acltype": {Value: "posix"}, "xattr": {Value: "on"}}}, nil); len(is) != 0 {
		t.Fatalf("xattr=on flagged: %+v", is)
	}
	px := DatasetACL{Props: map[string]ACLProp{"acltype": {Value: "posix"}, "xattr": {Value: "dir"}}}
	if is := ACLIssues(px, nil); len(is) != 1 || is[0].Level != "info" || SuggestedPreset(is) != "" {
		t.Fatalf("xattr %+v", is)
	}
}

func TestACLUsageFor(t *testing.T) {
	mounts := map[string]string{"/mnt/pool": "pool", "/mnt/pool/media": "pool/media", "/mnt/pool/media/tv": "pool/media/tv"}
	refs := []ACLShareRef{
		{Kind: "smb", Name: "all", Path: "/mnt/pool"},             // covers everything below
		{Kind: "smb", Name: "sub", Path: "/mnt/pool/media/films"}, // a folder of media
		{Kind: "nfs", Name: "/mnt/pool/media/tv", Path: "/mnt/pool/media/tv"},
		{Kind: "smb", Name: "media-ish", Path: "/mnt/pool/mediaX"}, // prefix lookalike: resolves to pool
	}
	names := func(r []ACLShareRef) []string {
		var n []string
		for _, x := range r {
			n = append(n, x.Name)
		}
		return n
	}
	media := DatasetACL{Name: "pool/media", Mountpoint: "/mnt/pool/media"}
	if got := names(ACLUsageFor(media, refs, mounts)); !reflect.DeepEqual(got, []string{"all", "sub"}) {
		t.Fatalf("media %v", got)
	}
	tv := DatasetACL{Name: "pool/media/tv", Mountpoint: "/mnt/pool/media/tv"}
	if got := names(ACLUsageFor(tv, refs, mounts)); !reflect.DeepEqual(got, []string{"all", "/mnt/pool/media/tv"}) {
		t.Fatalf("tv %v", got)
	}
}

func TestReviewSignatureOrderFree(t *testing.T) {
	if ReviewSignature([]string{"a", "b"}) != ReviewSignature([]string{"b", "a"}) || ReviewSignature([]string{"a"}) == ReviewSignature([]string{"b"}) {
		t.Fatal("signature")
	}
}
