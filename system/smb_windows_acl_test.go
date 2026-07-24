package system

import (
	"strings"
	"testing"
)

// The Windows ACL share option must NOT stack any ACL VFS module on Linux.
//
// History:
//   - ≤6.6.28: Windows ACL = POSIX-mode mapping + `force create mode = 0755`
//     (no ACL VFS module). Cross-user moves worked because deleting/renaming a
//     file is governed by POSIX write on the *parent directory*.
//   - 6.7.15–6.7.22: added `vfs objects = zfsacl` — a FreeBSD/illumos module
//     absent from Debian/Ubuntu, so shares refused every connection
//     (NT_STATUS_BAD_NETWORK_NAME).
//   - the zfsacl→nfs4acl_xattr fix: connections worked again, but nfs4acl_xattr
//     enforces NFSv4 DELETE semantics. Its POSIX-synthesized ACL grants group /
//     Everyone `0x001201bf` — WRITE but NOT `DELETE` (0x10000) on files nor
//     `DELETE_CHILD` (0x40) on directories — so only a file's owner could ever
//     move/rename/delete it. A second user with full write got ACCESS_DENIED
//     (verified on znas-debian2: the filesystem `mv` succeeded as the same user;
//     only Samba refused). That broke the common shared-folder workflow.
//
// Resolution (POSIX-mode, restoring the ≤6.6.28 behavior): emit no ACL VFS
// module, so Samba governs delete/rename by directory write like every other
// share. The exec bit is still preserved via `force create mode = 0755`.

func windowsACLShareBlock(t *testing.T) string {
	t.Helper()
	return renderManagedShares([]SMBShare{{
		Name:       "winacl",
		Path:       "/mnt/tank/winacl",
		Browseable: true,
		WindowsACL: true,
	}})
}

func vfsObjectsLine(got string) string {
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "vfs objects") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// TestWindowsACLUsesNoACLVFSModule is the core regression test for the
// cross-user move failure: no ACL VFS module may be stacked, because every one
// of them (zfsacl, nfs4acl_xattr, acl_xattr) imposes NT/NFSv4 DELETE semantics
// that withhold delete from non-owners who hold write.
func TestWindowsACLUsesNoACLVFSModule(t *testing.T) {
	vfsLine := vfsObjectsLine(windowsACLShareBlock(t))
	for _, mod := range []string{"zfsacl", "nfs4acl_xattr", "acl_xattr"} {
		if strings.Contains(vfsLine, mod) {
			t.Errorf("Windows ACL share stacked ACL module %q — breaks cross-user move/delete: %q", mod, vfsLine)
		}
	}
}

// TestWindowsACLKeepsFruitStack — fruit + streams_xattr remain (they are shared
// with the Time Machine / Apple-encoding options and carry no ACL semantics).
func TestWindowsACLKeepsFruitStack(t *testing.T) {
	vfsLine := vfsObjectsLine(windowsACLShareBlock(t))
	if vfsLine == "" {
		t.Fatalf("no vfs objects line rendered")
	}
	for _, mod := range []string{"fruit", "streams_xattr"} {
		if !strings.Contains(vfsLine, mod) {
			t.Errorf("vfs objects line dropped %s: %q", mod, vfsLine)
		}
	}
}

// TestWindowsACLKeepsExecBit — the one behavior the option must still provide:
// executables keep their +x bit via force create mode.
func TestWindowsACLKeepsExecBit(t *testing.T) {
	got := windowsACLShareBlock(t)
	if !strings.Contains(got, "force create mode = 0755") {
		t.Errorf("Windows ACL share dropped the exec-bit preservation:\n%s", got)
	}
}

// TestWindowsACLEmitsNoNFS4Params — none of the NFSv4-ACL wiring may remain;
// with no ACL module these parameters are inert at best and misleading at worst.
func TestWindowsACLEmitsNoNFS4Params(t *testing.T) {
	got := windowsACLShareBlock(t)
	for _, needle := range []string{"nfs4:", "nfs4acl_xattr:", "nt acl support", "zfsacl"} {
		if strings.Contains(got, needle) {
			t.Errorf("Windows ACL share still emits %q:\n%s", needle, got)
		}
	}
}

// TestWindowsACLCreateMask — the ≤6.6.28 masks are preserved (0744 for files so
// the exec bit survives the mask, 0775 for directories).
func TestWindowsACLCreateMask(t *testing.T) {
	got := windowsACLShareBlock(t)
	if !strings.Contains(got, "create mask = 0744") {
		t.Errorf("Windows ACL create mask changed:\n%s", got)
	}
	if !strings.Contains(got, "directory mask = 0775") {
		t.Errorf("directory mask changed:\n%s", got)
	}
}

// TestNonWindowsACLShareUnaffected — shares without the option must carry no ACL
// wiring at all.
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
// in the stack when both options are on.
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
