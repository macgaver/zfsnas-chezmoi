package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single audit log event.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	System    string    `json:"system,omitempty"` // hostname of the originating server (v6.4.28+: stamped at Read time for the local host; populated from peer name when merged from /api/audit/aggregate)
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Result    string    `json:"result"` // "ok" or "error"
	Details   string    `json:"details,omitempty"`
}

const (
	ResultOK    = "ok"
	ResultError = "error"
)

// Common action names.
const (
	ActionLogin           = "login"
	ActionLogout          = "logout"
	ActionLoginFailed     = "login_failed"
	ActionSetupAdmin      = "setup_admin"
	ActionCreateUser      = "create_user"
	ActionDeleteUser      = "delete_user"
	ActionUpdateUser      = "update_user"
	ActionKillSession     = "kill_session"
	ActionCreatePool      = "create_pool"
	ActionImportPool      = "import_pool"
	ActionCreateDataset   = "create_dataset"
	ActionUpdateDataset   = "update_dataset"
	ActionDeleteDataset   = "delete_dataset"
	ActionCreateShare     = "create_share"
	ActionDeleteShare     = "delete_share"
	ActionEnableShare     = "enable_share"
	ActionDisableShare    = "disable_share"
	ActionCreateSnapshot  = "create_snapshot"
	ActionDeleteSnapshot  = "delete_snapshot"
	ActionRestoreSnapshot = "restore_snapshot"
	ActionInstallPrereqs  = "install_prereqs"
	ActionInstallService  = "install_service"
	ActionMemCompEnable   = "mem_comp_enable"
	ActionMemCompDisable  = "mem_comp_disable"
	ActionMemCompConfig   = "mem_comp_config"
	ActionMemCompInstall  = "mem_comp_install"
	ActionNetworkMigrate  = "network_migrate"
	ActionApplyUpdates    = "apply_updates"
	ActionGrowPool        = "grow_pool"
	ActionExportPool      = "export_pool"
	ActionDestroyPool     = "destroy_pool"
	ActionUpgradePool     = "upgrade_pool"
	ActionUpdatePool      = "update_pool"
	ActionSystemReboot    = "system_reboot"
	ActionSystemShutdown  = "system_shutdown"
	ActionUpdateSettings  = "update_settings"
	ActionCreateNFSShare  = "create_nfs_share"
	ActionUpdateNFSShare  = "update_nfs_share"
	ActionDeleteNFSShare  = "delete_nfs_share"
	ActionCreateSchedule  = "create_schedule"
	ActionUpdateSchedule  = "update_schedule"
	ActionDeleteSchedule  = "delete_schedule"
	// External storage / Filesystem rsync events (v6.7.7).
	ActionExtStorageCreate = "extstorage_create"
	ActionExtStorageUpdate = "extstorage_update"
	ActionExtStorageDelete = "extstorage_delete"
	ActionRsyncRun         = "rsync_run"
	// Health events — logged automatically by the background health poller.
	ActionPoolProblem         = "pool_problem"
	ActionPoolRecovered       = "pool_recovered"
	ActionDiskProblem         = "disk_problem"
	ActionDiskRecovered       = "disk_recovered"
	ActionFolderScan          = "folder_scan"
	ActionTreeMapScheduleScan = "treemap_schedule_scan"
	// 2FA events.
	Action2FAEnabled  = "2fa_enabled"
	Action2FADisabled = "2fa_disabled"
	// Encryption key events.
	ActionGenerateKey = "generate_key"
	ActionImportKey   = "import_key"
	ActionDeleteKey   = "delete_key"
	ActionLoadKey     = "load_key"
	ActionUnloadKey   = "unload_key"
	// ZVol events.
	ActionCreateZVol = "create_zvol"
	ActionEditZVol   = "edit_zvol"
	ActionDeleteZVol = "delete_zvol"
	// iSCSI events.
	ActionEditISCSIConfig       = "edit_iscsi_config"
	ActionCreateISCSIShare      = "create_iscsi_share"
	ActionDeleteISCSIShare      = "delete_iscsi_share"
	ActionCreateISCSICredential = "create_iscsi_credential"
	ActionDeleteISCSICredential = "delete_iscsi_credential"
	// InterLink events.
	ActionInterlinkAccepted = "interlink_accepted"
	ActionInterlinkLinked   = "interlink_linked"
	ActionInterlinkUnlinked = "interlink_unlinked"
	// MinIO / S3 Object Server events.
	ActionEditMinIOConfig = "edit_minio_config"
	ActionCreateS3User    = "create_s3_user"
	ActionDeleteS3User    = "delete_s3_user"
	ActionCreateS3Bucket  = "create_s3_bucket"
	ActionDeleteS3Bucket  = "delete_s3_bucket"
	ActionEditS3Bucket    = "edit_s3_bucket"
	// Replication events.
	ActionCreateReplication = "create_replication"
	ActionEditReplication   = "edit_replication"
	ActionDeleteReplication = "delete_replication"
	ActionRunReplication    = "run_replication"
	// UPS events.
	ActionUPSOnBattery = "ups_on_battery"
	ActionUPSShutdown  = "ups_shutdown"
	// Push InterLink events.
	ActionPushInterlink = "push_interlink"
	// Software self-update.
	ActionSoftwareUpdate = "software_update"
	// Sudoers hardening.
	ActionUpdateSudoers = "update_sudoers"
	// File Browser.
	ActionFileBrowserChown  = "filebrowser_chown"
	ActionFileBrowserChmod  = "filebrowser_chmod"
	ActionFileBrowserMkdir  = "filebrowser_mkdir"
	ActionFileBrowserDelete = "filebrowser_delete"
	ActionFileBrowserMove   = "filebrowser_move"
	ActionFileBrowserCopy   = "filebrowser_copy"
	ActionFileBrowserUpload = "filebrowser_upload"
	// Dataset encryption actions.
	ActionLockDataset     = "lock_dataset"
	ActionUnlockDataset   = "unlock_dataset"
	ActionChangeKeySource = "change_key_source"
	// Access control.
	ActionForbidden = "forbidden_access"
	// Incus / VM events. Canonical action strings switched from "lxd_*" to
	// "incus_*" in v6.5.2. The old constants are kept as Go aliases pointing
	// to the new strings — old callers continue compiling. Audit log entries
	// written before 6.5.2 still parse fine (they're plain JSON strings); the
	// uniform-label helper in NormalizeAction translates them on read so the
	// Audit page UI shows the new label everywhere.
	ActionIncusCreateVM         = "incus_create_vm"
	ActionIncusCreateContainer  = "incus_create_container"
	ActionIncusStart            = "incus_start"
	ActionIncusStop             = "incus_stop"
	ActionIncusRestart          = "incus_restart"
	ActionIncusDelete           = "incus_delete"
	ActionIncusEditConfig       = "incus_edit_config"
	ActionIncusNetCreate        = "incus_net_create"
	ActionIncusNetEdit          = "incus_net_edit"
	ActionIncusNetDelete        = "incus_net_delete"
	ActionIncusSnapshot         = "incus_snapshot"
	ActionIncusRestore          = "incus_restore"
	ActionIncusDeleteSnapshot   = "incus_delete_snapshot"
	ActionIncusClone            = "incus_clone"
	ActionIncusMoveStorage      = "incus_move_storage"
	ActionIncusDiskMove         = "incus_disk_move" // v6.5.37 — per-disk move via Related Objects burger menu
	ActionProxmoxImport         = "proxmox_import"
	ActionIncusEnable           = "incus_enable"
	ActionIncusUninstall        = "incus_uninstall"
	ActionIncusStorageCreate    = "incus_storage_create"
	ActionIncusStorageEdit      = "incus_storage_edit"
	ActionIncusStorageDelete    = "incus_storage_delete"
	ActionIncusMetricsToggle    = "incus_metrics_toggle"     // v6.4.28 — enable/disable Incus prometheus endpoint + portal scraper
	ActionIncusGlobalConfigEdit = "incus_global_config_edit" // v6.4.28 — admin edited Incus global config keys
	ActionIncusStateChange      = "incus_state_change"       // v6.5.3 — VM/container changed runtime state (logged by the state watcher, including out-of-band changes)
	ActionISOUpload             = "iso_upload"               // v6.5.8 — ISO uploaded into <pool>/.isos/ via the ISO Management modal
	ActionISOFetch              = "iso_fetch"                // v6.5.8 — ISO downloaded from URL into <pool>/.isos/ via the server-side fetch job
	ActionISODelete             = "iso_delete"               // v6.5.8 — ISO removed from <pool>/.isos/

	// v6.5.19 — VM/Container backup feature.
	ActionLXDScheduledSnapshot  = "lxd_scheduled_snapshot"   // scheduler fired a per-instance snapshot
	ActionLXDBackup             = "lxd_backup"               // backup run (scheduled or "Backup Now")
	ActionLXDBackupSchedule     = "lxd_backup_schedule"      // user changed a backup policy
	ActionLXDBackupRestore      = "lxd_backup_restore"       // Instant Independent Restore (zfs clone of a backup)
	ActionLXDBackupCloneRestore = "lxd_backup_clone_restore" // clone-restore via syncoid
	ActionLXDBackupPromote      = "lxd_backup_promote"       // promote a backup-dependent clone to a full copy

	// Compose stack management.
	ActionComposeUpdate   = "compose_update"   // podman-compose pull + up -d on a stack
	ActionComposeRedeploy = "compose_redeploy" // compose file / .env edited and re-applied
	ActionComposeAction   = "compose_action"   // per-container start/stop/restart/update

	// v6.5.26 — Docker Detection inside user-managed VMs/LXCs.
	ActionDockerComposeEdit     = "docker_compose_edit"     // YAML edited + up -d
	ActionDockerComposeAction   = "docker_compose_action"   // per-stack start/stop/restart/pull/up
	ActionDockerContainerAction = "docker_container_action" // per-container start/stop/restart/update

	// Back-compat Go aliases. Old callers compile unchanged. ZNAS now writes
	// the new strings, but these aliases let imports that still say e.g.
	// `audit.ActionLXDStart` resolve to the new value seamlessly. Removed in
	// 6.5.5.
	ActionLXDCreateVM         = ActionIncusCreateVM
	ActionLXDCreateContainer  = ActionIncusCreateContainer
	ActionLXDStart            = ActionIncusStart
	ActionLXDStop             = ActionIncusStop
	ActionLXDRestart          = ActionIncusRestart
	ActionLXDDelete           = ActionIncusDelete
	ActionLXDEditConfig       = ActionIncusEditConfig
	ActionLXDNetCreate        = ActionIncusNetCreate
	ActionLXDNetEdit          = ActionIncusNetEdit
	ActionLXDNetDelete        = ActionIncusNetDelete
	ActionLXDSnapshot         = ActionIncusSnapshot
	ActionLXDRestore          = ActionIncusRestore
	ActionLXDDeleteSnapshot   = ActionIncusDeleteSnapshot
	ActionLXDClone            = ActionIncusClone
	ActionLXDMoveStorage      = ActionIncusMoveStorage
	ActionLXDEnable           = ActionIncusEnable
	ActionLXDUninstall        = ActionIncusUninstall
	ActionLXDStorageCreate    = ActionIncusStorageCreate
	ActionLXDStorageEdit      = ActionIncusStorageEdit
	ActionLXDStorageDelete    = ActionIncusStorageDelete
	ActionLXDMetricsToggle    = ActionIncusMetricsToggle
	ActionLXDGlobalConfigEdit = ActionIncusGlobalConfigEdit
	ActionLXDStateChange      = ActionIncusStateChange
)

// legacyActionMap maps pre-6.5.2 action strings to their canonical 6.5.2 form.
// Used by NormalizeAction to display old log entries with the new labels.
var legacyActionMap = map[string]string{
	"lxd_create_vm":          ActionIncusCreateVM,
	"lxd_create_container":   ActionIncusCreateContainer,
	"lxd_start":              ActionIncusStart,
	"lxd_stop":               ActionIncusStop,
	"lxd_restart":            ActionIncusRestart,
	"lxd_delete":             ActionIncusDelete,
	"lxd_edit_config":        ActionIncusEditConfig,
	"lxd_net_create":         ActionIncusNetCreate,
	"lxd_net_edit":           ActionIncusNetEdit,
	"lxd_net_delete":         ActionIncusNetDelete,
	"lxd_snapshot":           ActionIncusSnapshot,
	"lxd_restore":            ActionIncusRestore,
	"lxd_delete_snapshot":    ActionIncusDeleteSnapshot,
	"lxd_clone":              ActionIncusClone,
	"lxd_move_storage":       ActionIncusMoveStorage,
	"lxd_enable":             ActionIncusEnable,
	"lxd_storage_create":     ActionIncusStorageCreate,
	"lxd_storage_edit":       ActionIncusStorageEdit,
	"lxd_storage_delete":     ActionIncusStorageDelete,
	"lxd_metrics_toggle":     ActionIncusMetricsToggle,
	"lxd_global_config_edit": ActionIncusGlobalConfigEdit,
}

// NormalizeAction returns the canonical (6.5.2+) action string for a logged
// entry, translating any pre-6.5.2 lxd_* action to its incus_* counterpart.
// All other strings are returned unchanged.
func NormalizeAction(action string) string {
	if v, ok := legacyActionMap[action]; ok {
		return v
	}
	return action
}

var (
	logPath string
	mu      sync.Mutex
)

// Init sets the audit log file path.
func Init(configDir string) {
	logPath = filepath.Join(configDir, "audit.log")
}

// Log appends an entry to the audit log.
func Log(e Entry) {
	e.Timestamp = time.Now()
	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to open log: %v\n", err)
		return
	}
	defer f.Close()

	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s\n", data)
}

// Read loads all audit entries from the log file. Each entry's System
// field is stamped with the local hostname so callers (the multi-host
// aggregate handler in particular) can attribute it correctly.
func Read() ([]Entry, error) {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}

	host, _ := osHostname()
	var entries []Entry
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err == nil {
			if e.System == "" {
				e.System = host
			}
			e.Action = NormalizeAction(e.Action)
			entries = append(entries, e)
		}
	}
	return collapseLoginBursts(entries), nil
}

// collapseLoginBursts drops repeated SUCCESSFUL login entries for the same
// user + same client (Details carries "from <ip>") that land within one
// minute of the last kept one, so API-driven sessions and multi-tab logins
// don't flood the Activity & Events views with identical rows. Applied at
// Read time only — the on-disk log keeps every entry for forensics. Each
// kept entry opens a fresh 60s window; failed logins are never collapsed
// (a burst of failures is a signal, not noise). entries is oldest-first.
func collapseLoginBursts(entries []Entry) []Entry {
	lastKept := map[string]time.Time{}
	out := entries[:0]
	for _, e := range entries {
		if e.Action == ActionLogin && e.Result == ResultOK {
			key := e.User + "|" + e.Details
			if t, ok := lastKept[key]; ok && e.Timestamp.Sub(t) < time.Minute {
				continue
			}
			lastKept[key] = e.Timestamp
		}
		out = append(out, e)
	}
	return out
}

// osHostname is a thin wrapper around os.Hostname so callers always get a
// non-error path; an empty string means "couldn't resolve hostname" and
// the System field is left blank for that read.
var osHostname = func() (string, error) { return os.Hostname() }

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
