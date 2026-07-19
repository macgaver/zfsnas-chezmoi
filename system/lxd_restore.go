package system

// Restore helpers for the VM/Container backup feature (v6.5.19+).
//
// Two paths:
//   • Instant restore — rename in place. The bkup--<vm> Incus instance is
//     renamed to a user-chosen name and becomes a regular VM/Container.
//     No data is copied. Only valid when the backup lives on THIS host.
//   • Clone restore — syncoid copy of the backup dataset (local or remote)
//     into a chosen local Incus storage pool, then `incus admin recover` so
//     the new dataset shows up as a registered Incus instance.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// LXDInstantRestoreBackup turns a local backup into a regular Incus
// instance under <newName>, in place — no data is copied.
//
// v6.5.19+: backups live as plain ZFS datasets at
// "<zfs-pool>/ZNAS-Backups-Workload/<kind>/bkup--<vm>", NOT as registered
// Incus instances. So the operation is:
//
//  1. Locate the workload dataset on the named ZFS pool. zfsPool may be
//     "" in which case all imported pools are scanned for a match.
//  2. Find the Incus storage pool that uses this ZFS pool as source (the
//     "incus_datastore" surfaced by the picker). If none exists, the
//     restore is rejected — the dataset has nowhere to land that Incus
//     would discover.
//  3. zfs-rename the dataset (and its .block sibling) out of the workload
//     parent and INTO "<incus-pool-source>/<kind>/<newName>".
//  4. Rewrite backup.yaml (pool, instance name, clear snapshots).
//  5. Destroy snapshots on the renamed dataset so its count matches the
//     freshly cleared backup.yaml.
//  6. Run `incus admin recover` to register it.
//  7. Reset volatile state so the clone gets fresh MACs etc.
//
// The legacy code path (Incus-registered bkup--<vm>) is still attempted
// first when no workload dataset is found, so older test data still
// responds.
func LXDInstantRestoreBackup(vmID, newName, zfsPool, snapshotName string) error {
	return LXDInstantCloneRestore(vmID, newName, zfsPool, snapshotName, nil)
}

// LXDInstantCloneRestore performs an INSTANT INDEPENDENT RESTORE: it `zfs clone`s
// a LOCAL backup snapshot into the Incus storage pool backing the backup's ZFS
// pool, then `incus admin recover`s the clone as a new instance <newName>. The
// instance boots immediately off the clone and NEVER writes to the backup; the
// clone's `origin` is the backup snapshot, so the backup cannot be deleted until
// the instance is promoted to a full copy (see LXDPromoteToFullCopy).
//
// Constraints (vs the syncoid full-copy LXDCloneRestoreLocal):
//   - LOCAL only — `zfs clone` needs the snapshot on this host.
//   - The clone lands on the SAME ZFS pool as the backup (clones can't cross
//     pools), specifically the Incus pool whose source is that ZFS pool. If no
//     such Incus pool exists, instant restore is impossible here.
//
// snapshotName selects the point-in-time `snapshot-bkp-…` to clone; "" = latest.
func LXDInstantCloneRestore(vmID, newName, zfsPool, snapshotName string, logFn func(string)) error {
	if vmID == "" || newName == "" {
		return fmt.Errorf("vm_id and new_name are required")
	}
	if !lxdNameRe.MatchString(newName) {
		return fmt.Errorf("invalid new name %q (Incus naming rules)", newName)
	}
	if IsBackupInstanceName(newName) {
		return fmt.Errorf("new name cannot start with %q", LXDBackupPrefix)
	}
	if _, err := LXDGetStatus(newName); err == nil {
		return fmt.Errorf("instance %q already exists", newName)
	}

	backupName := LXDBackupPrefix + vmID
	pool, _ := findWorkloadBackup(backupName, zfsPool)
	if pool == "" {
		return fmt.Errorf("backup %s not found locally — Instant Independent Restore only works for backups stored on this host", backupName)
	}
	incusPool, dstSource := findIncusPoolForZFSPool(pool)
	if incusPool == "" || dstSource == "" {
		return fmt.Errorf("ZFS pool %q has no Incus storage pool — Instant Independent Restore can't land here (use Restore / Clone instead)", pool)
	}

	parts, kind, err := LXDBackupInstanceDatasets(backupName, pool)
	if err != nil {
		return fmt.Errorf("locate backup instance: %w", err)
	}

	// Resolve the canonical snapshot to clone from the root-fs part, then reuse
	// that exact name on the sibling parts (they share one atomic instance
	// snapshot). Fall back per-part if a custom volume lacks it.
	rootSnap := resolveCloneSnapshot(parts[0].SrcDataset, snapshotName)
	if rootSnap == "" {
		return fmt.Errorf("backup %s has no snapshot to restore from", backupName)
	}

	// Map each captured custom volume's original name → its restored name.
	volRemap := map[string]string{}
	for _, pt := range parts {
		if pt.Kind != "custom" {
			continue
		}
		origVol := strings.TrimPrefix(pt.DstBaseName, backupName+".")
		newVol := origVol
		if strings.Contains(origVol, vmID) {
			newVol = strings.Replace(origVol, vmID, newName, 1)
		} else {
			newVol = newName + "-" + origVol
		}
		volRemap[origVol] = newVol
	}

	dstParent := dstSource + "/" + kind
	_ = exec.Command("sudo", "zfs", "create", "-p", dstParent).Run()
	_ = exec.Command("sudo", "zfs", "create", "-p", dstSource+"/custom").Run()

	for _, part := range parts {
		finalBase := strings.Replace(part.DstBaseName, backupName, newName, 1)
		parent := dstParent
		if part.Kind == "custom" {
			parent = dstSource + "/custom"
			origVol := strings.TrimPrefix(part.DstBaseName, backupName+".")
			finalBase = "default_" + volRemap[origVol]
		}
		finalDataset := parent + "/" + finalBase
		// Pick the snapshot on THIS part: the canonical one if present, else its
		// own latest (custom volumes carry an independent syncoid snapshot too).
		snap := rootSnap
		if !datasetExists(part.SrcDataset + "@" + snap) {
			snap = resolveCloneSnapshot(part.SrcDataset, "")
			if snap == "" {
				return fmt.Errorf("backup part %s has no snapshot to clone", part.SrcDataset)
			}
		}
		// Clear any orphan at the final path (newName proven not a live instance).
		_ = exec.Command("sudo", "zfs", "destroy", "-r", finalDataset).Run()
		if logFn != nil {
			logFn(fmt.Sprintf("[%s] clone %s@%s -> %s", part.Kind, part.SrcDataset, snap, finalDataset))
		}
		if out, err := exec.Command("sudo", "zfs", "clone", part.SrcDataset+"@"+snap, finalDataset).CombinedOutput(); err != nil {
			return fmt.Errorf("zfs clone %s@%s: %s", part.SrcDataset, snap, strings.TrimSpace(string(out)))
		}
		if part.Kind == "root-fs" {
			if logFn != nil {
				logFn(fmt.Sprintf("Rewriting backup.yaml: pool→%s, name %s→%s, snapshots→[]", incusPool, vmID, newName))
			}
			if err := LXDRewriteBackupYAMLForRestore(finalDataset, incusPool, dstSource, vmID, newName, volRemap); err != nil && logFn != nil {
				logFn("rewrite backup.yaml: " + err.Error())
			}
		}
	}

	if logFn != nil {
		logFn("Running incus admin recover on " + incusPool)
	}
	out, err := LXDIncusAdminRecoverWithMask(newName)
	if logFn != nil {
		for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if ln != "" {
				logFn("  recover: " + ln)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("incus admin recover: %s", strings.TrimSpace(string(out)))
	}
	resetCloneVolatileState(newName, logFn)
	return nil
}

// resolveCloneSnapshot picks the snapshot short-name to clone from `dataset`.
// `preferred` (if it exists) wins; otherwise the newest "snapshot-bkp-*"; else
// the newest snapshot of any name. Returns "" when the dataset has none.
func resolveCloneSnapshot(dataset, preferred string) string {
	if preferred != "" && datasetExists(dataset+"@"+preferred) {
		return preferred
	}
	out, err := exec.Command("zfs", "list", "-Hp", "-t", "snapshot", "-o", "name", "-s", "creation", "-d", "1", dataset).Output()
	if err != nil {
		return ""
	}
	var lastBkp, lastAny string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		at := strings.IndexByte(name, '@')
		if at < 0 {
			continue
		}
		short := name[at+1:]
		lastAny = short
		// Backup fires land as "snapshot-bkp-to-<label>-<date>" on the backup
		// dataset; prefer those over any stray syncoid_* sync snapshot.
		if strings.Contains(short, "bkp-to-") {
			lastBkp = short
		}
	}
	if lastBkp != "" {
		return lastBkp
	}
	return lastAny
}

// BackupOrigin describes one instance dataset that is a ZFS clone of a backup
// snapshot (the hallmark of an Instant Independent Restore).
type BackupOrigin struct {
	Dataset    string `json:"dataset"`
	Origin     string `json:"origin"`       // full "<ds>@<snap>" the clone hangs off
	BackupVMID string `json:"backup_vm_id"` // the bkup--<vm> name
	BackupPool string `json:"backup_pool"`  // ZFS pool holding the backup
	Snapshot   string `json:"snapshot"`     // short snapshot name
}

// LXDInstanceBackupOrigins returns the datasets of instance `name` whose ZFS
// `origin` is a snapshot under the ZNAS-Backups-Workload tree — i.e. the
// instance is running off a backup clone and is "backup dependent". Empty slice
// (nil) means fully independent storage.
func LXDInstanceBackupOrigins(name string) ([]BackupOrigin, error) {
	parts, err := LXDInstanceBackupDatasets(name)
	if err != nil {
		return nil, err
	}
	marker := "/" + LXDBackupWorkloadMarker + "/"
	var res []BackupOrigin
	for _, p := range parts {
		origin := ZfsOrigin(p.SrcDataset)
		if origin == "" || !strings.Contains(origin, marker) {
			continue
		}
		bo := BackupOrigin{Dataset: p.SrcDataset, Origin: origin}
		if i := strings.Index(origin, marker); i > 0 {
			bo.BackupPool = origin[:i]
		}
		if at := strings.LastIndexByte(origin, '@'); at >= 0 {
			bo.Snapshot = origin[at+1:]
		}
		// origin path holds "…/bkup--<vm>[.<vol>]@<snap>"; extract <vm>.
		if bi := strings.Index(origin, "/"+LXDBackupPrefix); bi >= 0 {
			rest := origin[bi+len("/"+LXDBackupPrefix):]
			if at := strings.IndexByte(rest, '@'); at >= 0 {
				rest = rest[:at]
			}
			if dot := strings.IndexByte(rest, '.'); dot >= 0 {
				rest = rest[:dot]
			}
			bo.BackupVMID = rest
		}
		res = append(res, bo)
	}
	return res, nil
}

// incusPoolNameForSource returns the Incus storage-pool NAME whose zfs `source`
// is exactly `src`, or "" if none matches.
func incusPoolNameForSource(src string) string {
	pools, _ := LXDListStoragePools()
	for _, p := range pools {
		if LXDStoragePoolSource(p) == src {
			return p
		}
	}
	return ""
}

// LXDPromoteToFullCopy turns a backup-dependent instance (one running off a ZFS
// clone of a backup — an Instant Independent Restore) into an independent full
// copy on `dstDatastore`, freeing the backup. The instance MUST be Stopped. The
// CURRENT (live) state is copied, so any changes made since the instant restore
// are preserved.
//
// Steps: full-copy every live dataset (send/recv = independent) into a landing
// dataset; delete the clone instance + its clone datasets/volumes (frees the
// backup snapshot); move the landings into place; rewrite backup.yaml for the
// new pool; `incus admin recover` to re-register under the SAME name.
func LXDPromoteToFullCopy(ctx context.Context, name, dstDatastore string, logFn func(string)) error {
	if !lxdNameRe.MatchString(name) {
		return fmt.Errorf("invalid instance name %q", name)
	}
	status, err := LXDGetStatus(name)
	if err != nil {
		return fmt.Errorf("instance %q not found", name)
	}
	if !strings.EqualFold(status, "Stopped") {
		return fmt.Errorf("%s must be Stopped before promoting to a Full Copy (current: %s)", name, status)
	}
	origins, _ := LXDInstanceBackupOrigins(name)
	if len(origins) == 0 {
		return fmt.Errorf("%s is not running off a backup clone — nothing to promote", name)
	}
	incusPool, dstSource := resolveDstDatastore(dstDatastore)
	if dstSource == "" {
		return fmt.Errorf("destination datastore %q is neither an Incus storage pool nor a ZFS pool backed by one", dstDatastore)
	}
	dstDatastore = incusPool // normalize (caller may pass the ZFS pool name)
	parts, err := LXDInstanceBackupDatasets(name)
	if err != nil {
		return fmt.Errorf("enumerate instance datasets: %w", err)
	}

	kind := "virtual-machines"
	for _, p := range parts {
		if p.Kind == "root-fs" && strings.Contains(p.SrcDataset, "/containers/") {
			kind = "containers"
		}
	}
	dstParent := dstSource + "/" + kind
	_ = exec.Command("sudo", "zfs", "create", "-p", dstParent).Run()
	_ = exec.Command("sudo", "zfs", "create", "-p", dstSource+"/custom").Run()

	type promoteMove struct {
		landing, final, srcDs, kind string
	}
	type custVol struct{ pool, vol string }
	var moves []promoteMove
	var custVols []custVol
	volRemap := map[string]string{} // name unchanged → identity

	// 1) Full-copy each live (clone) dataset to an independent landing dataset.
	//    ownSnap=true → syncoid snapshots the CURRENT state (keeps post-restore
	//    changes); send/recv always yields a clone-free (origin "-") copy.
	for _, part := range parts {
		base := part.SrcDataset[strings.LastIndex(part.SrcDataset, "/")+1:]
		parent := dstParent
		if part.Kind == "custom" {
			parent = dstSource + "/custom"
			vol := strings.TrimPrefix(base, "default_")
			volRemap[vol] = vol
			srcRoot := part.SrcDataset[:strings.Index(part.SrcDataset, "/custom/")]
			if pn := incusPoolNameForSource(srcRoot); pn != "" {
				custVols = append(custVols, custVol{pool: pn, vol: vol})
			}
		}
		landing := parent + "/incoming-restore-promote-" + base
		final := parent + "/" + base
		_ = exec.Command("sudo", "zfs", "destroy", "-r", landing).Run()
		if logFn != nil {
			logFn(fmt.Sprintf("[%s] full-copy %s -> %s", part.Kind, part.SrcDataset, final))
		}
		if err := RunSyncoidLocal(ctx, part.SrcDataset, landing, part.Recursive, true, logFn); err != nil {
			return err
		}
		moves = append(moves, promoteMove{landing: landing, final: final, srcDs: part.SrcDataset, kind: part.Kind})
	}

	// 2) Remove the backup-dependent clone instance + its clone datasets/volumes
	//    → the backup snapshot's last clone is gone, so the backup is free again.
	if logFn != nil {
		logFn("Removing the backup-dependent clone " + name + " …")
	}
	_ = exec.Command("incus", "delete", "-f", name).Run()
	for _, cv := range custVols {
		_ = exec.Command("incus", "storage", "volume", "delete", cv.pool, cv.vol).Run()
	}
	for _, m := range moves {
		_ = exec.Command("sudo", "zfs", "destroy", "-r", m.srcDs).Run()
	}

	// 3) Move the independent copies into place + rewrite backup.yaml.
	var rootFinal string
	for _, m := range moves {
		_ = exec.Command("sudo", "zfs", "destroy", "-r", m.final).Run()
		if out, err := exec.Command("sudo", "zfs", "rename", m.landing, m.final).CombinedOutput(); err != nil {
			return fmt.Errorf("zfs rename %s -> %s: %s", m.landing, m.final, strings.TrimSpace(string(out)))
		}
		destroyDatasetSnapshots(m.final, logFn)
		if m.kind == "root-fs" {
			rootFinal = m.final
		}
	}
	if rootFinal != "" {
		if logFn != nil {
			logFn(fmt.Sprintf("Rewriting backup.yaml: pool→%s, snapshots→[]", dstDatastore))
		}
		if err := LXDRewriteBackupYAMLForRestore(rootFinal, dstDatastore, dstSource, name, name, volRemap); err != nil && logFn != nil {
			logFn("rewrite backup.yaml: " + err.Error())
		}
	}

	// 4) Re-register the now-independent instance under the same name.
	if logFn != nil {
		logFn("Running incus admin recover on " + dstDatastore)
	}
	out, err := LXDIncusAdminRecoverWithMask(name)
	if logFn != nil {
		for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if ln != "" {
				logFn("  recover: " + ln)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("incus admin recover: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// findWorkloadBackup locates the workload-layout backup for `bkup--<vm>`.
// When zfsPool is empty, it scans every imported pool; otherwise only that
// pool is checked. Returns the pool and the kind ("virtual-machines" or
// "containers") when found; ("","") otherwise.
func findWorkloadBackup(backupName, zfsPool string) (string, string) {
	pools, _ := ListLocalZFSPools()
	if zfsPool != "" {
		pools = []string{zfsPool}
	}
	for _, pool := range pools {
		parent := LXDWorkloadBackupParent(pool)
		for _, kind := range []string{"virtual-machines", "containers"} {
			if datasetExists(parent + "/" + kind + "/" + backupName) {
				return pool, kind
			}
		}
	}
	return "", ""
}

// findIncusPoolForZFSPool returns the (Incus pool name, its zfs `source`)
// for the Incus storage pool that uses `zfsPool` as its top-level pool.
// Returns ("","") when none is configured (or Incus isn't installed).
// resolveDstDatastore accepts a restore destination that may be given as either
// an Incus storage-pool name (e.g. "default") or a ZFS pool name (e.g.
// "nvmepool") and returns the canonical (incusPool, source). This lets API
// callers pass the ZFS pool name for dst_datastore consistently with the
// backup path's dest_pool / restore src_datastore (both ZFS pool names),
// instead of only the Incus pool name. Returns ("","") when neither resolves.
func resolveDstDatastore(dstDatastore string) (incusPool, source string) {
	if src := getLXDPoolSource(dstDatastore); src != "" {
		return dstDatastore, src // already an Incus storage-pool name
	}
	return findIncusPoolForZFSPool(dstDatastore) // maybe a ZFS pool name
}

func findIncusPoolForZFSPool(zfsPool string) (string, string) {
	pools, _ := LXDListStoragePools()
	want := strings.ToLower(zfsPool)
	for _, p := range pools {
		src := LXDStoragePoolSource(p)
		if src == "" {
			continue
		}
		root := src
		if i := strings.IndexByte(src, '/'); i > 0 {
			root = src[:i]
		}
		if strings.ToLower(root) == want {
			return p, src
		}
	}
	return "", ""
}

// LXDCloneRestoreLocal performs a clone-restore from a local bkup--<vmID>
// dataset on this host into a chosen local Incus storage pool, registering
// the resulting dataset as a fresh Incus instance named <cloneName>.
//
// When `snapshotName` is non-empty, the cloned destination dataset is
// rolled back to that exact snapshot before `incus admin recover` runs —
// so the resulting instance reflects the VM state at that point in time
// instead of the latest. Empty `snapshotName` keeps the latest state.
//
// Steps:
//  1. resolve source dataset (this host)
//  2. resolve destination dataset (local Incus pool with kind matching)
//  3. syncoid local replication
//  4. zfs rename the received bkup--<vmID> dataset to <cloneName>
//  5. zfs rollback -r <dst>@<snapshotName>  (if snapshotName != "")
//  6. incus admin recover on the destination pool so it surfaces
func LXDCloneRestoreLocal(ctx context.Context, vmID, srcDatastore, dstDatastore, cloneName, snapshotName string, logFn func(string)) error {
	if !lxdNameRe.MatchString(cloneName) {
		return fmt.Errorf("invalid clone name %q", cloneName)
	}
	if IsBackupInstanceName(cloneName) {
		return fmt.Errorf("clone name cannot start with %q", LXDBackupPrefix)
	}
	if _, err := LXDGetStatus(cloneName); err == nil {
		return fmt.Errorf("instance %q already exists", cloneName)
	}

	incusPool, dstSource := resolveDstDatastore(dstDatastore)
	if dstSource == "" {
		return fmt.Errorf("destination datastore %q is neither an Incus storage pool nor a ZFS pool backed by one", dstDatastore)
	}
	dstDatastore = incusPool // normalize (caller may pass the ZFS pool name)

	backupName := LXDBackupPrefix + vmID

	// v6.5.19: backups are not registered with Incus, so we enumerate
	// their constituent datasets via ZFS scan instead of `incus list`.
	// This also returns the detected `kind` ("virtual-machines" or
	// "containers") since we can't query Incus for that either.
	parts, kind, err := LXDBackupInstanceDatasets(backupName, srcDatastore)
	if err != nil {
		return fmt.Errorf("locate backup instance: %w", err)
	}

	// Map each captured custom volume's original name → the name it's restored
	// under. Same on recovery (cloneName==vmID); on clone-to-new-name we make
	// it unique so it can't collide with the still-running source's volume.
	// Attached disk devices whose volume ISN'T captured get stripped.
	volRemap := map[string]string{}
	for _, pt := range parts {
		if pt.Kind != "custom" {
			continue
		}
		origVol := strings.TrimPrefix(pt.DstBaseName, backupName+".")
		newVol := origVol
		if cloneName != vmID {
			if strings.Contains(origVol, vmID) {
				newVol = strings.Replace(origVol, vmID, cloneName, 1)
			} else {
				newVol = cloneName + "-" + origVol
			}
		}
		volRemap[origVol] = newVol
	}

	// Ensure parent destination datasets exist.
	dstParent := dstSource + "/" + kind
	_ = exec.Command("sudo", "zfs", "create", "-p", dstParent).Run()
	_ = exec.Command("sudo", "zfs", "create", "-p", dstSource+"/custom").Run()

	// For each part, syncoid into a temporary landing dataset, then rename
	// to the user-chosen name. The naming substitutes bkup--<vmID> in the
	// part's DstBaseName with the user's cloneName so the renamed instance
	// is internally consistent (e.g. ".block" zvol carries the new name).
	for _, part := range parts {
		// Replace the "bkup--<vmID>" prefix in the part's basename so the
		// landing dataset already carries the clone name (Incus naming
		// rules: the .block sibling and custom volumes must share the
		// instance name).
		finalBase := strings.Replace(part.DstBaseName, LXDBackupPrefix+vmID, cloneName, 1)
		parent := dstParent
		if part.Kind == "custom" {
			// Incus custom volumes are datasets named "<src>/custom/<project>_<vol>".
			parent = dstSource + "/custom"
			origVol := strings.TrimPrefix(part.DstBaseName, backupName+".")
			finalBase = "default_" + volRemap[origVol]
		}
		landingBase := "incoming-restore-" + finalBase
		landingDataset := parent + "/" + landingBase
		finalDataset := parent + "/" + finalBase

		// Clean up orphans from a prior FAILED restore of the same clone
		// name — both the landing and the final path. The clone name was
		// already proven to not be a registered Incus instance, so any
		// dataset here is a leftover, safe to destroy. Without the final-
		// path destroy, the post-syncoid rename fails "already exists".
		_ = exec.Command("sudo", "zfs", "destroy", "-r", landingDataset).Run()
		_ = exec.Command("sudo", "zfs", "destroy", "-r", finalDataset).Run()

		if logFn != nil {
			logFn(fmt.Sprintf("[%s] %s -> %s", part.Kind, part.SrcDataset, finalDataset))
		}
		// Restore reads from a backup dataset that already carries snapshots, so
		// use the existing ones (ownSnap=false → --no-sync-snap).
		if err := RunSyncoidLocal(ctx, part.SrcDataset, landingDataset, part.Recursive, false, logFn); err != nil {
			return err
		}
		if out, err := exec.Command("sudo", "zfs", "rename", landingDataset, finalDataset).CombinedOutput(); err != nil {
			return fmt.Errorf("zfs rename: %s", strings.TrimSpace(string(out)))
		}
		// Roll the dataset back to the user-picked snapshot so the
		// resulting clone reflects that point in time. Skipped when
		// snapshotName=="" (latest). Custom volumes are skipped — their
		// snapshot history is independent from the instance's
		// `incus snapshot create` cadence and that point-in-time name
		// won't exist on them.
		if snapshotName != "" && (part.Kind == "root-fs" || part.Kind == "root-blk") {
			rollbackTarget := finalDataset + "@" + snapshotName
			if logFn != nil {
				logFn("Rolling " + finalDataset + " back to @" + snapshotName)
			}
			if out, err := exec.Command("sudo", "zfs", "rollback", "-r", rollbackTarget).CombinedOutput(); err != nil {
				return fmt.Errorf("zfs rollback to @%s: %s", snapshotName, strings.TrimSpace(string(out)))
			}
		}
		// Destroy snapshot history on the cloned dataset — Incus refuses
		// a dataset whose snapshot count doesn't match backup.yaml's
		// `snapshots:` list, and we rewrite that list to [] just below.
		// Done on every part, root-fs + .block + custom, so they stay
		// aligned with each other and with backup.yaml.
		destroyDatasetSnapshots(finalDataset, logFn)
		// On the root-fs part: rewrite the embedded backup.yaml so its
		// pool, instance name, and (now-empty) snapshot list match the
		// destination dataset state. Without this `incus admin recover`
		// rejects the dataset.
		if part.Kind == "root-fs" {
			if logFn != nil {
				logFn(fmt.Sprintf("Rewriting backup.yaml: pool→%s, name %s→%s, snapshots→[]", dstDatastore, vmID, cloneName))
			}
			if err := LXDRewriteBackupYAMLForRestore(finalDataset, dstDatastore, dstSource, vmID, cloneName, volRemap); err != nil {
				if logFn != nil {
					logFn("rewrite backup.yaml: " + err.Error())
				}
			}
		}
	}

	// Trigger Incus recovery so the new dataset becomes a real instance.
	if logFn != nil {
		logFn("Running incus admin recover on " + dstDatastore)
	}
	out, err := LXDIncusAdminRecoverWithMask(cloneName)
	if logFn != nil {
		for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if ln != "" {
				logFn("  recover: " + ln)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("incus admin recover: %s", strings.TrimSpace(string(out)))
	}
	// Clear volatile state copied from the original so the clone gets
	// fresh MAC addresses, UUIDs etc. — otherwise it collides with the
	// running source instance on start. Best-effort.
	resetCloneVolatileState(cloneName, logFn)
	return nil
}

// resetCloneVolatileState prepares a freshly restored instance to live
// alongside the original it was copied from. It:
//   - turns OFF auto-start on boot (boot.autostart) and ZNAS force-running
//     (user.zfsnas.force_running) — a restore is a COPY and must not race the
//     original to auto-start on host boot or be auto-restarted by ZNAS; the
//     user re-enables them deliberately if they want.
//   - clears NIC-related `volatile.*` keys so Incus regenerates fresh MAC
//     addresses on next start (volatile.uuid is NOT touched — Incus parses it
//     on load and refuses an empty value).
//
// The targeted volatile keys: anything matching volatile.*.hwaddr (NIC MACs),
// volatile.vsock_id (would collide with the source VM), and
// volatile.cloud-init.instance-id (so cloud-init treats the clone as a
// new instance).
func resetCloneVolatileState(instance string, logFn func(string)) {
	// Disable auto-start-on-boot and force-running up front, before the
	// volatile-key scan below (which can return early once the config section
	// ends), so a restored copy never fights the original instance.
	for _, kv := range [][2]string{{"boot.autostart", "false"}, {"user.zfsnas.force_running", "false"}} {
		if err := exec.Command("incus", "config", "set", instance, kv[0], kv[1]).Run(); err == nil {
			if logFn != nil {
				logFn("  set " + kv[0] + "=" + kv[1] + " (restored copy)")
			}
		}
	}

	out, err := exec.Command("incus", "config", "show", instance).Output()
	if err != nil {
		return
	}
	inConfig := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "config:" {
			inConfig = true
			continue
		}
		if !inConfig {
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			return
		}
		eq := strings.Index(trimmed, ":")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		if shouldResetVolatileKey(key) {
			if uerr := exec.Command("incus", "config", "unset", instance, key).Run(); uerr == nil {
				if logFn != nil {
					logFn("  unset " + key)
				}
			}
		}
	}
}

// shouldResetVolatileKey returns true for the narrow set of volatile keys
// that must NOT carry over from the original VM to the clone.
func shouldResetVolatileKey(key string) bool {
	if !strings.HasPrefix(key, "volatile.") {
		return false
	}
	if strings.HasSuffix(key, ".hwaddr") {
		return true
	}
	switch key {
	case "volatile.vsock_id",
		"volatile.cloud-init.instance-id",
		"volatile.last_state.power":
		return true
	}
	return false
}

// destroyDatasetSnapshots wipes all snapshots from `dataset`. Best-effort —
// errors are logged but not returned because restore can still succeed even
// if one stray snapshot lingers (Incus will refuse and the user can re-run).
func destroyDatasetSnapshots(dataset string, logFn func(string)) {
	out, err := exec.Command("zfs", "list", "-Hpt", "snapshot", "-o", "name", "-r", dataset).Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		snap := strings.TrimSpace(line)
		if snap == "" {
			continue
		}
		// Only this exact dataset's snapshots, not children.
		if !strings.HasPrefix(snap, dataset+"@") {
			continue
		}
		if dout, derr := exec.Command("sudo", "zfs", "destroy", snap).CombinedOutput(); derr != nil {
			if logFn != nil {
				logFn("destroy " + snap + ": " + strings.TrimSpace(string(dout)))
			}
		}
	}
}

// LXDCloneRestoreRemote performs a clone-restore where the source backup
// lives on a remote ZNAS peer reached over SSH.
//
// vmID is the original instance name on the peer (e.g. "vm-1"). It is
// needed to (a) probe for the VM's .block sibling zvol on the remote, and
// (b) rewrite backup.yaml so its `name:` field matches `cloneName` on
// recovery. `srcDataset` is the root-fs dataset path on the remote.
//
// `snapshotName` works the same as in LXDCloneRestoreLocal — empty means
// "latest"; otherwise the destination dataset is rolled back to that
// snapshot after syncoid pull.
func LXDCloneRestoreRemote(ctx context.Context, srcHost, srcUser, srcDataset, dstDatastore, cloneName, snapshotName, vmID, knownHostsFile string, logFn func(string)) error {
	if !lxdNameRe.MatchString(cloneName) {
		return fmt.Errorf("invalid clone name %q", cloneName)
	}
	if IsBackupInstanceName(cloneName) {
		return fmt.Errorf("clone name cannot start with %q", LXDBackupPrefix)
	}
	if _, err := LXDGetStatus(cloneName); err == nil {
		return fmt.Errorf("instance %q already exists", cloneName)
	}

	incusPool, dstSource := resolveDstDatastore(dstDatastore)
	if dstSource == "" {
		return fmt.Errorf("destination datastore %q is neither an Incus storage pool nor a ZFS pool backed by one", dstDatastore)
	}
	dstDatastore = incusPool // normalize (caller may pass the ZFS pool name)

	// Heuristic to find the kind from the source dataset path: look for the
	// "virtual-machines" or "containers" segment.
	kind := "virtual-machines"
	if strings.Contains(srcDataset, "/containers/") {
		kind = "containers"
	}

	dstParent := dstSource + "/" + kind
	_ = exec.Command("sudo", "zfs", "create", "-p", dstParent).Run()
	_ = exec.Command("sudo", "zfs", "create", "-p", dstSource+"/custom").Run()

	// pull syncoid-pulls one remote dataset into <parent>/<landingBase> then
	// renames it to <parent>/<finalBase>, returning the final path. allowRollback
	// applies the chosen point-in-time snapshot (root-fs/.block only — custom
	// volumes have an independent snapshot history). Any pre-existing landing/
	// final dataset (orphan from a prior failed restore of this clone name) is
	// destroyed first; the LXDGetStatus check above proved <cloneName> isn't a
	// registered instance, so that's safe.
	pull := func(remoteSrc, parent, landingBase, finalBase string, recursive, allowRollback bool) (string, error) {
		landing := parent + "/" + landingBase
		final := parent + "/" + finalBase
		_ = exec.Command("sudo", "zfs", "destroy", "-r", landing).Run()
		_ = exec.Command("sudo", "zfs", "destroy", "-r", final).Run()
		if logFn != nil {
			logFn(fmt.Sprintf("Pulling %s:%s -> %s", srcHost, remoteSrc, landing))
		}
		if err := RunSyncoidRestore(ctx, srcHost, srcUser, remoteSrc, landing, recursive, knownHostsFile, logFn); err != nil {
			return "", err
		}
		if out, err := exec.Command("sudo", "zfs", "rename", landing, final).CombinedOutput(); err != nil {
			return "", fmt.Errorf("zfs rename: %s", strings.TrimSpace(string(out)))
		}
		if allowRollback && snapshotName != "" {
			if logFn != nil {
				logFn("Rolling " + final + " back to @" + snapshotName)
			}
			if out, err := exec.Command("sudo", "zfs", "rollback", "-r", final+"@"+snapshotName).CombinedOutput(); err != nil {
				return "", fmt.Errorf("zfs rollback to @%s: %s", snapshotName, strings.TrimSpace(string(out)))
			}
		}
		destroyDatasetSnapshots(final, logFn)
		return final, nil
	}

	// 1. Root filesystem dataset (always present).
	rootFinal, err := pull(srcDataset, dstParent, "incoming-restore-"+cloneName, cloneName, true, true)
	if err != nil {
		return err
	}

	// 2. VM root .block zvol — the actual disk; its absence is fatal (a diskless
	//    instance is useless). "could not find any snapshots" means the backup
	//    itself is incomplete.
	if kind == "virtual-machines" {
		if _, err := pull(srcDataset+".block", dstParent, "incoming-restore-"+cloneName+".block", cloneName+".block", false, true); err != nil {
			if strings.Contains(err.Error(), "could not find any snapshots") {
				return fmt.Errorf("the backup on the source is incomplete — its disk image (%s.block) has no snapshots. "+
					"Re-run the backup of this VM to that destination, then retry the restore. (%w)", srcDataset, err)
			}
			return err
		}
	}

	// 3. Attached custom-volume vdisks. Enumerate the peer's
	//    <workload>/custom/bkup--<vm>.<vol> datasets over the same SSH access
	//    syncoid uses, pull each to <dstSource>/custom/default_<newVol>, and build
	//    the source→restored-name remap so backup.yaml keeps the disk devices
	//    (pointing at the restored volumes) instead of stripping them. This is
	//    what makes a remote restore include EVERY disk, like the local path.
	volRemap := map[string]string{}
	customParent := lxdRemoteWorkloadCustomParent(srcDataset, kind)
	for _, vol := range lxdListRemoteCustomBackupVols(ctx, srcHost, srcUser, customParent, vmID) {
		newVol := vol
		if cloneName != vmID {
			if strings.Contains(vol, vmID) {
				newVol = strings.Replace(vol, vmID, cloneName, 1)
			} else {
				newVol = cloneName + "-" + vol
			}
		}
		volRemap[vol] = newVol
		remoteSrc := customParent + "/" + LXDBackupPrefix + vmID + "." + vol
		if _, err := pull(remoteSrc, dstSource+"/custom", "incoming-restore-default_"+newVol, "default_"+newVol, true, false); err != nil {
			return fmt.Errorf("restore custom volume %q: %w", vol, err)
		}
	}

	// 4. Rewrite the root-fs backup.yaml: dst pool/name, empty snapshots, KEEP the
	//    captured custom-disk devices (source-remapped + pool-rewritten to dst),
	//    strip host-path devices (cdrom/ISO) and any uncaptured custom volume.
	if logFn != nil {
		logFn(fmt.Sprintf("Rewriting backup.yaml: pool→%s, name %s→%s, snapshots→[]", dstDatastore, vmID, cloneName))
	}
	if err := LXDRewriteBackupYAMLForRestore(rootFinal, dstDatastore, dstSource, vmID, cloneName, volRemap); err != nil {
		if logFn != nil {
			logFn("rewrite backup.yaml: " + err.Error())
		}
	}

	if logFn != nil {
		logFn("Running incus admin recover on " + dstDatastore)
	}
	out, err := LXDIncusAdminRecoverWithMask(cloneName)
	if logFn != nil {
		for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if ln != "" {
				logFn("  recover: " + ln)
			}
		}
	}
	if err != nil {
		return fmt.Errorf("incus admin recover: %s", strings.TrimSpace(string(out)))
	}
	// Clear volatile.eth0.hwaddr etc so the clone gets fresh values on
	// next start instead of colliding with the source VM's MAC.
	resetCloneVolatileState(cloneName, logFn)
	return nil
}

// lxdRemoteWorkloadCustomParent derives the peer's workload custom-volume parent
// (<workload>/custom) from a root-fs backup dataset path
// (<workload>/<kind>/bkup--<vm>). Returns "" if the kind segment isn't found.
func lxdRemoteWorkloadCustomParent(rootFSDataset, kind string) string {
	seg := "/" + kind + "/"
	i := strings.LastIndex(rootFSDataset, seg)
	if i < 0 {
		return ""
	}
	return rootFSDataset[:i] + "/custom"
}

// lxdListRemoteCustomBackupVols lists the custom-volume names captured for `vmID`
// in the peer's backup, by SSH-listing the direct children of `customParent` and
// keeping those named "bkup--<vm>.<vol>". Uses the same key/user syncoid pulls
// with — and syncoid already requires `zfs list` on the source, so this works
// wherever a pull would. Returns nil on any error (no custom dir / none / denied).
func lxdListRemoteCustomBackupVols(ctx context.Context, host, user, customParent, vmID string) []string {
	if customParent == "" || host == "" {
		return nil
	}
	args := []string{"-i", zfsnasSSHKey(),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "ConnectTimeout=10",
		user + "@" + host,
		"zfs list -H -o name -r -d 1 " + customParent}
	out, err := exec.CommandContext(ctx, "ssh", args...).Output()
	if err != nil {
		return nil
	}
	prefix := customParent + "/" + LXDBackupPrefix + vmID + "."
	var vols []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		ds := strings.TrimSpace(line)
		if strings.HasPrefix(ds, prefix) {
			vols = append(vols, ds[len(prefix):])
		}
	}
	return vols
}
