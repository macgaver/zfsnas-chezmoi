package system

import (
	"strings"
	"testing"
)

// The Windows ACL share option shipped `vfs objects = zfsacl` from v6.7.15
// (commit 6b4a729) through v6.7.22.  vfs_zfsacl is a FreeBSD/illumos module
// that Debian and Ubuntu do not build — no zfsacl.so exists in either distro's
// samba packaging — so smbd failed to load it and every affected share answered
// tree connects with NT_STATUS_BAD_NETWORK_NAME:
//
//	Error loading module '/usr/lib/x86_64-linux-gnu/samba/vfs/zfsacl.so':
//	  cannot open shared object file: No such file or directory
//	error probing vfs module 'zfsacl': NT_STATUS_UNSUCCESSFUL
//	smbd_vfs_init: vfs_init_custom failed for zfsacl
//
// The Linux equivalent that ships in both distros is vfs_nfs4acl_xattr.

func windowsACLShareBlock(t *testing.T) string {
	t.Helper()
	return renderManagedShares([]SMBShare{{
		Name:       "winacl",
		Path:       "/mnt/tank/winacl",
		Browseable: true,
		WindowsACL: true,
	}})
}

// TestWindowsACLDoesNotEmitZfsacl is the core regression test: the module that
// does not exist on Debian/Ubuntu must never reach smb.conf again.
func TestWindowsACLDoesNotEmitZfsacl(t *testing.T) {
	got := windowsACLShareBlock(t)
	if strings.Contains(got, "zfsacl") {
		t.Errorf("Windows ACL share emitted the unloadable zfsacl module:\n%s", got)
	}
}

// TestWindowsACLUsesNfs4aclXattr checks we use the module Debian/Ubuntu do ship.
func TestWindowsACLUsesNfs4aclXattr(t *testing.T) {
	got := windowsACLShareBlock(t)
	var vfsLine string
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "vfs objects") {
			vfsLine = strings.TrimSpace(line)
		}
	}
	if vfsLine == "" {
		t.Fatalf("no vfs objects line rendered:\n%s", got)
	}
	if !strings.Contains(vfsLine, "nfs4acl_xattr") {
		t.Errorf("vfs objects line missing nfs4acl_xattr: %q", vfsLine)
	}
	// fruit/streams_xattr were already stacked for this option; keep them.
	for _, mod := range []string{"fruit", "streams_xattr"} {
		if !strings.Contains(vfsLine, mod) {
			t.Errorf("vfs objects line dropped %s: %q", mod, vfsLine)
		}
	}
}

// TestWindowsACLDisablesValidateMode guards a silent-data-loss footgun.
// For the ndr/xdr encodings nfs4acl_xattr:validate_mode defaults to YES, which
// makes the module discard the stored ACL blob unless the POSIX mode is exactly
// 0777 on directories and 0666 on files.  We write create mask = 0744 and
// directory mask = 0775, so every ACL would be thrown away on read.
func TestWindowsACLDisablesValidateMode(t *testing.T) {
	got := windowsACLShareBlock(t)
	if !strings.Contains(got, "nfs4acl_xattr:validate_mode = no") {
		t.Errorf("validate_mode not disabled — stored ACLs would be discarded because our masks are not 0777/0666:\n%s", got)
	}
}

// TestWindowsACLPinsEncoding — the default encoding differs across Samba
// releases, and each encoding uses a different xattr to store the blob.
// Letting it drift would orphan every previously stored ACL, so pin it.
func TestWindowsACLPinsEncoding(t *testing.T) {
	got := windowsACLShareBlock(t)
	if !strings.Contains(got, "nfs4acl_xattr:encoding = ndr") {
		t.Errorf("encoding not pinned to ndr:\n%s", got)
	}
}

// TestWindowsACLStoresBlobInUserNamespace guards the difference between
// "Windows can view permissions" and "Windows can change permissions".
//
// The ndr/xdr encodings default to storing the ACL blob in security.nfs4acl_*.
// Linux restricts writes to the security.* xattr namespace to CAP_SYS_ADMIN,
// and smbd runs as the connecting user once authenticated, so every attempt to
// apply an ACL failed on the test VM with:
//
//	smbcacls: NT_STATUS_ACCESS_DENIED
//	vfs_nfs4acl_xattr.c:284: can't store acl in xattr: Operation not permitted
//
// Relocating the blob into the user.* namespace makes ACL writes work; the
// module never elevates privileges the way vfs_acl_xattr does.
func TestWindowsACLStoresBlobInUserNamespace(t *testing.T) {
	got := windowsACLShareBlock(t)
	const want = "nfs4acl_xattr:xattr_name = user.nfs4acl_ndr"
	if !strings.Contains(got, want) {
		t.Errorf("ACL blob left in the privileged security.* namespace — clients can read ACLs but every write returns ACCESS_DENIED; want %q in:\n%s", want, got)
	}
}

// TestWindowsACLAvoidsDeprecatedNfs4Mode — vfs_nfs4acl_xattr(8) marks
// "nfs4:mode = special" deprecated and recommends simple.  The zfsacl-era code
// wrote special; since the module never loaded, nothing depended on it.
func TestWindowsACLAvoidsDeprecatedNfs4Mode(t *testing.T) {
	got := windowsACLShareBlock(t)
	if strings.Contains(got, "nfs4:mode = special") {
		t.Errorf("uses deprecated nfs4:mode = special:\n%s", got)
	}
	if !strings.Contains(got, "nfs4:mode = simple") {
		t.Errorf("missing nfs4:mode = simple:\n%s", got)
	}
}

// TestNonWindowsACLShareUnaffected — shares without the option must not gain
// any NFSv4 ACL wiring.
func TestNonWindowsACLShareUnaffected(t *testing.T) {
	got := renderManagedShares([]SMBShare{{
		Name:       "plain",
		Path:       "/mnt/tank/plain",
		Browseable: true,
	}})
	for _, needle := range []string{"nfs4acl_xattr", "nfs4:", "zfsacl", "nt acl support"} {
		if strings.Contains(got, needle) {
			t.Errorf("plain share leaked %q:\n%s", needle, got)
		}
	}
}

// TestWindowsACLKeepsShadowCopyFirst — shadow_copy2 must stay the first module
// in the stack; adding the ACL module must not displace it.
func TestWindowsACLKeepsShadowCopyFirst(t *testing.T) {
	got := renderManagedShares([]SMBShare{{
		Name:       "both",
		Path:       "/mnt/tank/both",
		WindowsACL: true,
		ShadowCopy: true,
	}})
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "vfs objects") {
			mods := strings.Fields(strings.SplitN(line, "=", 2)[1])
			if len(mods) == 0 || mods[0] != "shadow_copy2" {
				t.Errorf("shadow_copy2 is not first: %q", strings.TrimSpace(line))
			}
		}
	}
}

// ---- repair of smb.conf files already poisoned by 6.7.15–6.7.22 ----

// TestStripZfsaclKeepsOtherModules — the module list must survive minus zfsacl.
func TestStripZfsaclKeepsOtherModules(t *testing.T) {
	in := "[Videos]\n   path = /BIGRAID5/Videos\n   vfs objects = zfsacl fruit streams_xattr\n"
	got := stripZfsaclVFSObject(in)
	if strings.Contains(got, "zfsacl") {
		t.Errorf("zfsacl not stripped: %q", got)
	}
	if !strings.Contains(got, "vfs objects = fruit streams_xattr") {
		t.Errorf("other modules mangled: %q", got)
	}
	if !strings.Contains(got, "path = /BIGRAID5/Videos") {
		t.Errorf("unrelated lines lost: %q", got)
	}
}

// TestStripZfsaclPreservesLeadingModules — the observed .5 config had catia
// ahead of zfsacl; ordering of the survivors must not change.
func TestStripZfsaclPreservesLeadingModules(t *testing.T) {
	in := "   vfs objects = catia zfsacl fruit streams_xattr\n"
	got := stripZfsaclVFSObject(in)
	if !strings.Contains(got, "vfs objects = catia fruit streams_xattr") {
		t.Errorf("module order changed: %q", got)
	}
}

// TestStripZfsaclDropsEmptyLine — "vfs objects = zfsacl" alone must not leave a
// dangling "vfs objects =" behind, which Samba logs as an empty module list.
func TestStripZfsaclDropsEmptyLine(t *testing.T) {
	in := "[s]\n   path = /x\n   vfs objects = zfsacl\n   browseable = yes\n"
	got := stripZfsaclVFSObject(in)
	if strings.Contains(got, "vfs objects") {
		t.Errorf("empty vfs objects line left behind: %q", got)
	}
	if !strings.Contains(got, "browseable = yes") || !strings.Contains(got, "path = /x") {
		t.Errorf("adjacent lines lost: %q", got)
	}
}

// TestStripZfsaclIndifferentToSpacing — hand-edited files use varied spacing.
func TestStripZfsaclIndifferentToSpacing(t *testing.T) {
	for _, in := range []string{
		"vfs objects=zfsacl fruit\n",
		"   VFS OBJECTS = zfsacl fruit\n",
		"\tvfs objects  =  zfsacl   fruit\n",
	} {
		got := stripZfsaclVFSObject(in)
		if strings.Contains(strings.ToLower(got), "zfsacl") {
			t.Errorf("zfsacl survived %q -> %q", in, got)
		}
		if !strings.Contains(got, "fruit") {
			t.Errorf("fruit lost from %q -> %q", in, got)
		}
	}
}

// TestStripZfsaclLeavesCleanConfUntouched — the repair must be a no-op on files
// that were never poisoned, including ones already using nfs4acl_xattr.
func TestStripZfsaclLeavesCleanConfUntouched(t *testing.T) {
	in := "[ok]\n   vfs objects = nfs4acl_xattr fruit streams_xattr\n   nfs4:mode = simple\n"
	if got := stripZfsaclVFSObject(in); got != in {
		t.Errorf("clean conf modified:\n%q\nwant:\n%q", got, in)
	}
}

// TestStripZfsaclIsIdempotent — startup runs this on every boot.
func TestStripZfsaclIsIdempotent(t *testing.T) {
	in := "   vfs objects = catia zfsacl fruit\n"
	once := stripZfsaclVFSObject(in)
	if twice := stripZfsaclVFSObject(once); twice != once {
		t.Errorf("not idempotent: %q then %q", once, twice)
	}
}

// TestStripZfsaclOnlyTouchesVFSObjectsLines — a share or path that merely
// contains the word must not be edited.
func TestStripZfsaclOnlyTouchesVFSObjectsLines(t *testing.T) {
	in := "[zfsacl]\n   path = /mnt/tank/zfsacl\n   comment = zfsacl notes\n"
	if got := stripZfsaclVFSObject(in); got != in {
		t.Errorf("non-vfs line edited:\n%q", got)
	}
}
