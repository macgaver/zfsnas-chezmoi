package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/secret"
)

// ReplicationTask defines a ZFS send/receive replication job to a remote host.
type ReplicationTask struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	SourceDataset string    `json:"source_dataset"`      // full path: pool/dataset
	RemoteHost    string    `json:"remote_host"`         // hostname or IP
	RemoteUser    string    `json:"remote_user"`         // SSH user (default: root)
	RemoteDataset string    `json:"remote_dataset"`      // destination: pool/dataset
	Recursive     bool      `json:"recursive"`           // -R flag: include child datasets
	Compressed    bool      `json:"compressed"`          // -c flag: send compressed stream
	LastSnap      string    `json:"last_snap,omitempty"` // last successfully sent snapshot (for incremental)
	LastRun       time.Time `json:"last_run,omitempty"`
	LastStatus    string    `json:"last_status,omitempty"` // "ok", "error", "never"
	LastMessage   string    `json:"last_message,omitempty"`
}

const (
	RoleAdmin    = "admin"
	RoleReadOnly = "read-only"
	RoleSMBOnly  = "smb-only"
	RoleStandard = "standard"
)

// StandardPermissions holds granular capability flags for a "standard" role user.
// All fields are omitempty so the struct serialises to {} when all are false.
type StandardPermissions struct {
	Terminal          bool `json:"terminal,omitempty"`
	ReviewSudoers     bool `json:"review_sudoers,omitempty"`
	BrowseFiles       bool `json:"browse_files,omitempty"`
	ManagePoolDataset bool `json:"manage_pool_dataset,omitempty"`
	ManageSMB         bool `json:"manage_smb,omitempty"`
	ManageNFS         bool `json:"manage_nfs,omitempty"`
	ManageISCSI       bool `json:"manage_iscsi,omitempty"`
	ManageProtection  bool `json:"manage_protection,omitempty"`
	ManageSnapshots   bool `json:"manage_snapshots,omitempty"`
	EditSettings      bool `json:"edit_settings,omitempty"`
	ManageInterlink   bool `json:"manage_interlink,omitempty"`
	// ManageDockerDetect gates the Docker Detection card on a VM/LXC's
	// main page. Independent from CreateContainer/EditInstances so an
	// admin can let a standard user manage in-guest Docker stacks
	// without granting Incus-level mutation rights on the instance.
	ManageDockerDetect bool `json:"manage_docker_detect,omitempty"`
	// Virtualization tab capabilities. All default false — pre-existing
	// standard users get no VM/container/networking access until an admin
	// explicitly grants it.
	ViewVirtualization    bool `json:"view_virtualization,omitempty"`     // see the Compute (VMs & Containers) section at all
	ViewServices          bool `json:"view_services,omitempty"`           // v6.8.1 — see the Services category and open a service's web UI through the proxy
	ManageServices        bool `json:"manage_services,omitempty"`         // v6.8.1 — edit/create/delete services and start/stop/restart their containers
	CreateVM              bool `json:"create_vm,omitempty"`               // create new VMs
	CreateContainer       bool `json:"create_container,omitempty"`        // create new containers
	EditInstances         bool `json:"edit_instances,omitempty"`          // edit config of existing VMs/containers
	ControlInstances      bool `json:"control_instances,omitempty"`       // start/stop/restart/console
	DeleteInstances       bool `json:"delete_instances,omitempty"`        // delete VMs/containers
	ManageInstanceBackups bool `json:"manage_instance_backups,omitempty"` // VM/container backups & snapshots
	ViewNetworking        bool `json:"view_networking,omitempty"`         // see the Networking section at all
	ManageNetworking      bool `json:"manage_networking,omitempty"`       // create/edit/delete bridges & networks
	// InstanceVisibilityRegex, when non-empty, restricts which instances a
	// standard user can see/act on: only VMs/containers whose ID matches this
	// regular expression are visible. Empty = no restriction (all visible).
	InstanceVisibilityRegex string `json:"instance_visibility_regex,omitempty"`
}

// InstanceVisible reports whether an instance with the given ID/name is
// visible to a user holding these permissions. An empty or invalid regex
// means "no restriction". Used to filter VM/container lists for standard
// users so they only see the workloads an admin whitelisted for them.
func (p *StandardPermissions) InstanceVisible(instanceID string) bool {
	if p == nil || strings.TrimSpace(p.InstanceVisibilityRegex) == "" {
		return true
	}
	re, err := regexp.Compile(p.InstanceVisibilityRegex)
	if err != nil {
		return true // a broken regex must not lock the user out of everything
	}
	return re.MatchString(instanceID)
}

// S3Bucket is a MinIO bucket managed by ZFSNAS and tracked in portal config.
type S3Bucket struct {
	Name       string   `json:"name"`
	Comment    string   `json:"comment"`
	Versioning string   `json:"versioning"`  // "off", "enabled", "suspended"
	ObjectLock bool     `json:"object_lock"` // immutable after creation
	Quota      string   `json:"quota"`       // human string e.g. "50G", "" = unlimited
	AnonAccess string   `json:"anon_access"` // "none", "download", "public"
	UserKeys   []string `json:"user_keys"`
	CreatedAt  int64    `json:"created_at"`
}

// MinIOConfig holds all persistent MinIO / S3 Object Server settings.
type MinIOConfig struct {
	Enabled      bool       `json:"enabled"`
	HideNav      bool       `json:"hide_nav"`                // hide nav item when not installed
	DatasetPath  string     `json:"dataset_path"`            // ZFS dataset path used as backend
	DataDir      string     `json:"data_dir"`                // absolute mountpoint of that dataset
	Port         int        `json:"port"`                    // API port, default 9000
	ConsolePort  int        `json:"console_port"`            // web console port, default 9001
	TLS          bool       `json:"tls"`                     // enable TLS on both ports
	TLSCertName  string     `json:"tls_cert_name,omitempty"` // "" or "auto" = generate new self-signed
	RootUser     string     `json:"root_user"`
	RootPassword string     `json:"root_password"`
	Region       string     `json:"region"`
	SiteName     string     `json:"site_name"`
	ServerURL    string     `json:"server_url"`
	Buckets      []S3Bucket `json:"buckets"`
}

// ISCSIHost is a known initiator that can be granted access to iSCSI shares.
type ISCSIHost struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IQN     string `json:"iqn"`
	Comment string `json:"comment"`
}

// ISCSICredential is a named CHAP authentication credential for iSCSI.
type ISCSICredential struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Method      string `json:"method"`      // "incoming" or "bidirectional"
	InUsername  string `json:"in_username"` // initiator → target authentication
	InPassword  string `json:"in_password"`
	OutUsername string `json:"out_username,omitempty"` // target → initiator (bidirectional only)
	OutPassword string `json:"out_password,omitempty"`
}

// ISCSIShare is a single exported iSCSI target backed by a ZVol.
type ISCSIShare struct {
	ID        string            `json:"id"`
	ZVol      string            `json:"zvol"`
	IQN       string            `json:"iqn"`
	HostIDs   []string          `json:"host_ids"`
	HostCreds map[string]string `json:"host_creds,omitempty"` // hostID → credID
	Comment   string            `json:"comment"`
	CreatedAt int64             `json:"created_at"`
}

// ISCSIConfig holds all persistent iSCSI settings.
type ISCSIConfig struct {
	Enabled     bool              `json:"enabled"`
	HideNav     bool              `json:"hide_nav"` // hide nav item when not installed
	BaseName    string            `json:"base_name"`
	Port        int               `json:"port"`
	Hosts       []ISCSIHost       `json:"hosts"`
	Shares      []ISCSIShare      `json:"shares"`
	Credentials []ISCSICredential `json:"credentials,omitempty"`
}

// UPSShutdownPolicy defines when to automatically shut down the system.
type UPSShutdownPolicy struct {
	Enabled          bool   `json:"enabled"`
	TriggerType      string `json:"trigger_type"`      // "time" | "percent" | "both"
	RuntimeThreshold int    `json:"runtime_threshold"` // shut down when runtime < N seconds (0 = disabled)
	PercentThreshold int    `json:"percent_threshold"` // shut down when charge < N% (0 = disabled)
	PreShutdownCmd   string `json:"pre_shutdown_cmd,omitempty"`
}

// NUTServerConfig holds settings for running this machine as a NUT network server
// (MODE=netserver). Remote NUT clients can query this host for UPS data.
type NUTServerConfig struct {
	// ListenIP is the IP address upsd binds to. Default "0.0.0.0" (all interfaces).
	ListenIP string `json:"listen_ip"`
	// ListenPort is the NUT protocol port. Default 3493.
	ListenPort int `json:"listen_port"`
	// AllowedClients is a list of IP addresses or CIDR ranges allowed to connect.
	AllowedClients []string `json:"allowed_clients,omitempty"`
	// RemoteUsers is the list of NUT user accounts written to upsd.users for
	// remote clients. Each user needs at minimum upsmon slave access.
	RemoteUsers []NUTRemoteUser `json:"remote_users,omitempty"`
}

// NUTRemoteUser represents a user entry in /etc/nut/upsd.users for remote access.
type NUTRemoteUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
	// Role: "upsmon" (monitoring only) | "admin" (full control)
	Role string `json:"role"`
}

// NUTClientConfig holds connectivity settings for connecting to a remote NUT server
// (MODE=netclient). The local UPS driver is not started in this mode.
type NUTClientConfig struct {
	Host     string `json:"host"`               // hostname or IP of remote NUT server
	Port     int    `json:"port"`               // NUT port, default 3493
	UPSName  string `json:"ups_name"`           // UPS name on the remote server
	Username string `json:"username,omitempty"` // NUT username for upsmon slave
	Password string `json:"password,omitempty"` // NUT password
}

// UPSConfig holds all persistent UPS / NUT settings.
type UPSConfig struct {
	Enabled bool `json:"enabled"`
	// Mode: "standalone" | "network_server" | "network_client"
	// Default (empty) = "standalone" for backward compatibility.
	Mode string `json:"mode,omitempty"`
	// --- Standalone / Network Server fields (local hardware) ---
	UPSName         string            `json:"ups_name"`
	Driver          string            `json:"driver"`
	Port            string            `json:"port"`
	MonitorPassword string            `json:"monitor_password,omitempty"`
	RawUPSConf      string            `json:"raw_ups_conf,omitempty"` // original nut-scanner output, base for ups.conf
	ShutdownPolicy  UPSShutdownPolicy `json:"shutdown_policy"`
	NominalPowerW   *int              `json:"nominal_power_w,omitempty"` // user-overridable nominal VA/W rating
	// CostCentsPerKWh is the user's electricity rate in cents per kWh
	// (integer cents, e.g. 12 for $0.12/kWh). Used by the UI to surface a
	// $/Year estimate next to the Load %; nil when the user hasn't set it.
	CostCentsPerKWh *int `json:"cost_cents_per_kwh,omitempty"`
	// --- Network Server extra fields ---
	NUTServer *NUTServerConfig `json:"nut_server,omitempty"`
	// --- Network Client fields ---
	NUTClient *NUTClientConfig `json:"nut_client,omitempty"`
}

// DiskPowerConfig holds hdparm-based power management settings applied to all
// physical (non-ZFS-metadata) block devices via /etc/hdparm.conf on boot.
type DiskPowerConfig struct {
	Enabled bool `json:"enabled"`
	// APMLevel: 1-127 (spindown allowed), 128-254 (no spindown), 255 (disable APM). 0 = not configured.
	APMLevel int `json:"apm_level"`
	// SpindownTimeout: 0=disabled, 1-240=multiples of 5s, 241-251=multiples of 30min. Passed to hdparm -S.
	SpindownTimeout int `json:"spindown_timeout"`
	// WriteCache: nil=don't set, true=enable (-W1), false=disable (-W0).
	WriteCache *bool `json:"write_cache,omitempty"`
	// AcousticLevel: -1=not configured, 0=disabled/vendor default, 128=quiet, 254=fast.
	AcousticLevel int `json:"acoustic_level"`
}

// SystemPowerConfig holds platform-level power management settings.
// These are intended for always-on NAS systems — the UI warns users about
// the trade-offs of aggressive power saving on a server.
type SystemPowerConfig struct {
	// CPUGovernor: "performance"|"powersave"|"ondemand"|"conservative"|"schedutil"|""
	CPUGovernor string `json:"cpu_governor,omitempty"`
	// PowerProfile: "performance"|"balanced"|"power-saver"|""
	PowerProfile string `json:"power_profile,omitempty"`
	// USBAutosuspend: nil=don't change, true=enable (2s delay), false=disable.
	USBAutosuspend *bool `json:"usb_autosuspend,omitempty"`
	// PCIeASPM: "default"|"performance"|"powersave"|"powersupersave"|""
	PCIeASPM string `json:"pcie_aspm,omitempty"`
}

// LXDSnapshotPolicy is a per-instance scheduled snapshot policy (v6.5.19).
// One policy per instance; identified by Instance. Stored as a slice on
// AppConfig so a single JSON write covers all changes.
type LXDSnapshotPolicy struct {
	Instance     string `json:"instance"` // Incus instance name (the only key)
	Enabled      bool   `json:"enabled"`
	EveryN       int    `json:"every_n"`               // 1..N
	Unit         string `json:"unit"`                  // "minute"|"hour"|"day"|"week"|"month"
	HourOfDay    int    `json:"hour_of_day,omitempty"` // 0-23, used only when Unit>="day"
	MinuteOfHour int    `json:"minute_of_hour"`        // 0-59, used at all granularities
	// Weekday: 0=Sun..6=Sat. Used only when Unit=="week". v6.5.19+.
	Weekday int `json:"weekday,omitempty"`
	// DayOfMonth: 1..31. Used only when Unit=="month". Clamped to the
	// month's last calendar day when the chosen day doesn't exist (e.g.
	// DOM=31 on a 30-day month fires on day 30). v6.5.19+.
	DayOfMonth int    `json:"day_of_month,omitempty"`
	NamePrefix string `json:"name_prefix"` // e.g. "auto" → "auto-2026-05-19-1300"
	KeepLast   int    `json:"keep_last"`   // retention by count

	LastRun    time.Time `json:"last_run,omitempty"`
	LastStatus string    `json:"last_status,omitempty"` // "ok" | "error" | ""
	LastError  string    `json:"last_error,omitempty"`
	LastSnap   string    `json:"last_snap,omitempty"`
}

// LXDBackupPolicy is a per-instance scheduled backup (syncoid replication)
// policy (v6.5.19). One policy per instance; the destination can be a local
// or a remote (interlink) datastore.
type LXDBackupPolicy struct {
	Instance string `json:"instance"`
	Enabled  bool   `json:"enabled"`

	DestKind     string `json:"dest_kind"`                // "local" | "remote"
	DestServerID string `json:"dest_server_id,omitempty"` // populated when DestKind=="remote"
	DestPool     string `json:"dest_pool"`                // Incus storage-pool name on the destination side

	EveryN       int    `json:"every_n"`
	Unit         string `json:"unit"` // "minute"|"hour"|"day"|"week"|"month"
	HourOfDay    int    `json:"hour_of_day,omitempty"`
	MinuteOfHour int    `json:"minute_of_hour"`
	// v6.5.19+: same semantics as on LXDSnapshotPolicy.
	Weekday    int `json:"weekday,omitempty"`
	DayOfMonth int `json:"day_of_month,omitempty"`

	RetentionKind  string `json:"retention_kind"` // "count" | "age"
	RetentionCount int    `json:"retention_count,omitempty"`
	RetentionAgeN  int    `json:"retention_age_n,omitempty"`
	RetentionAgeU  string `json:"retention_age_unit,omitempty"` // "hours"|"days"|"weeks"|"months"

	// Compression — ZFS compression algorithm applied to the destination
	// workload parent dataset. Affects only NEW data written into the
	// backup; existing data on previously-created backup datasets keeps
	// the property they were created with. Default "zstd-19" (max ratio).
	// Allowed: "zstd-19", "zstd-9", "zstd-3", "lz4", "off".
	Compression string `json:"compression,omitempty"`

	LastRun    time.Time `json:"last_run,omitempty"`
	LastStatus string    `json:"last_status,omitempty"`
	LastError  string    `json:"last_error,omitempty"`
	LastBytes  int64     `json:"last_bytes,omitempty"`
}

// ComposeUpdatePolicy is a per-stack scheduled auto-update policy. One policy
// per Compose stack, identified by Instance (the Incus container name). An
// update runs `podman-compose pull` + `podman-compose up -d` inside the stack.
// Stored as a slice on AppConfig so a single JSON write covers all changes.
type ComposeUpdatePolicy struct {
	Instance     string `json:"instance"`
	Enabled      bool   `json:"enabled"`
	EveryN       int    `json:"every_n"`                // 1..N
	Unit         string `json:"unit"`                   // "minute"|"hour"|"day"|"week"|"month"
	HourOfDay    int    `json:"hour_of_day,omitempty"`  // 0-23, used when Unit>="day"
	MinuteOfHour int    `json:"minute_of_hour"`         // 0-59
	Weekday      int    `json:"weekday,omitempty"`      // 0=Sun..6=Sat, Unit=="week"
	DayOfMonth   int    `json:"day_of_month,omitempty"` // 1..31, Unit=="month"

	LastRun    time.Time `json:"last_run,omitempty"`
	LastStatus string    `json:"last_status,omitempty"` // "ok" | "error" | ""
	LastError  string    `json:"last_error,omitempty"`
}

// LinkedServer represents a remote ZNAS instance trusted for single-click SSO switching.
type LinkedServer struct {
	ID             string    `json:"id"`            // our local UUID for this link
	URL            string    `json:"url"`           // e.g. "https://nas.example.com:8443"
	Hostname       string    `json:"hostname"`      // remote hostname, fetched at link time
	SharedSecret   string    `json:"shared_secret"` // 32-byte hex; HMAC signing key for SSO tokens
	RemoteID       string    `json:"remote_id"`     // the ID the remote server uses for this link (sent in redirect)
	LinkedBy       string    `json:"linked_by"`     // admin username who created the link
	LinkedAt       time.Time `json:"linked_at"`
	TLSFingerprint string    `json:"tls_fingerprint,omitempty"` // SHA-256 hex of peer TLS cert (TOFU pin)
	LXDTrusted     bool      `json:"lxd_trusted,omitempty"`     // true once LXD cert exchange completed successfully
}

// VersionCacheEntry holds the last fetched GitHub release check result,
// cached server-side to avoid hitting the API on every page load.
type VersionCacheEntry struct {
	CheckedAt        int64  `json:"checked_at"` // Unix timestamp (seconds)
	Latest           string `json:"latest"`
	UpdateAvailable  bool   `json:"update_available"`
	SigValid         bool   `json:"sig_valid"`
	SigError         string `json:"sig_error,omitempty"`
	DownloadURL      string `json:"download_url,omitempty"`
	ServiceInstalled bool   `json:"service_installed"`
}

// PoolScrubPolicy holds the scrub schedule for one ZFS pool. Set
// Schedule="" to mean "no scrub on this pool"; Hour is 0-23 host-local.
// v6.5.26+ — replaces the single-global ScrubSchedule/ScrubHour on
// multi-pool hosts.
type PoolScrubPolicy struct {
	Pool     string `json:"pool"`
	Schedule string `json:"schedule"` // "" | "weekly" | "biweekly" | "monthly" | "2months" | "4months"
	Hour     int    `json:"hour"`     // 0-23
}

// AppConfig holds top-level application settings.
type AppConfig struct {
	ConfigDir string `json:"-"` // runtime-only, not persisted
	Port      int    `json:"port"`
	// BindPort443, when true, also listens on the standard HTTPS port 443 in
	// addition to Port. Binding the privileged port from the non-root service
	// account is granted via a systemd CAP_NET_BIND_SERVICE drop-in.
	BindPort443 bool `json:"bind_port_443,omitempty"`
	// ComposeBaseImage is the LXC base image used for Compose stacks
	// ("alpine" | "debian" | "ubuntu"). Empty defaults to "debian".
	ComposeBaseImage string `json:"compose_base_image,omitempty"`
	// Docker Detection (v6.5.26) — when enabled, the portal probes each
	// VM or LXC the user opens for a running Docker daemon and renders
	// a Docker card listing the containers/stacks found. Pointers so an
	// absent value means "never configured" and defaults ON (v6.6.9); an
	// explicit false (admin opted out per type from Settings → Virtualization)
	// is preserved. Read via DockerDetectVMsOn / DockerDetectContainersOn.
	DockerDetectVMs        *bool     `json:"docker_detect_vms,omitempty"`
	DockerDetectContainers *bool     `json:"docker_detect_containers,omitempty"`
	StorageUnit            string    `json:"storage_unit,omitempty"` // "gb" (1000-based) or "gib" (1024-based)
	LoginTheme             string    `json:"login_theme,omitempty"`  // "dark" | "light" | "auto"
	SMARTLastRefresh       time.Time `json:"smart_last_refresh,omitempty"`
	WeeklyScrub            bool      `json:"weekly_scrub"`             // deprecated: migrated to ScrubSchedule
	ScrubSchedule          string    `json:"scrub_schedule,omitempty"` // legacy global (pre-v6.5.26): default for pools without an entry in ScrubPolicies
	ScrubHour              int       `json:"scrub_hour"`               // legacy global hour, used the same way (default 2)
	// ScrubPolicies stores per-pool scrub schedules (v6.5.26+). Each
	// entry overrides the legacy global ScrubSchedule/ScrubHour for that
	// one pool. Pools with no entry inherit the global (or no scrub at
	// all if the global is "" too). The slice is the authoritative store;
	// the global fields are kept for back-compat with older configs and
	// single-pool installs that never opened the new per-pool UI.
	ScrubPolicies []PoolScrubPolicy `json:"scrub_policies,omitempty"`
	// v6.5.30 — persistent terminal sessions
	TerminalScrollbackKB       int `json:"terminal_scrollback_kb,omitempty"`         // per-session scrollback ring in KB; 0 = default (256)
	TerminalMaxSessionsPerUser int `json:"terminal_max_sessions_per_user,omitempty"` // cap of live PTYs per web user; 0 = default (20)

	LiveUpdateEnabled       bool                  `json:"live_update_enabled,omitempty"`    // enable in-place binary self-update
	VersionCheckInterval    string                `json:"version_check_interval,omitempty"` // daily (default) | weekly | monthly | manual
	VersionCheckCache       *VersionCacheEntry    `json:"version_check_cache,omitempty"`    // server-side cache of last GitHub check
	AutoUpdateEnabled       bool                  `json:"auto_update_enabled,omitempty"`    // automatically apply updates at scheduled hour
	AutoUpdateHour          int                   `json:"auto_update_hour"`                 // hour of day (0-23) to run auto-update, default 3
	MaxSmbdProcesses        int                   `json:"max_smbd_processes,omitempty"`     // Samba max smbd processes (0 = use default 100)
	SMBHomeDataset          string                `json:"smb_home_dataset,omitempty"`       // ZFS dataset path for SMB user home folders; "" = disabled
	SMBCleanDefaults        bool                  `json:"smb_clean_defaults,omitempty"`     // remove distro default [printers], [print$], [homes] sections
	SMBWorkgroup            string                `json:"smb_workgroup,omitempty"`          // Samba workgroup name (default "WORKGROUP")
	SMBCustomGlobal         string                `json:"smb_custom_global,omitempty"`      // extra lines appended to the managed [global] section
	SMBSocketOptions        bool                  `json:"smb_socket_options,omitempty"`     // enable socket options for throughput (TCP_NODELAY, buffers)
	TreeMapSchedule         string                `json:"treemap_schedule,omitempty"`       // daily | weekly | biweekly | monthly | "" (off)
	TreeMapHour             int                   `json:"treemap_hour"`                     // hour of day to run treemap scan (0-23)
	TreeMapMinute           int                   `json:"treemap_minute"`                   // minute of hour to run treemap scan (0-59)
	ISCSI                   ISCSIConfig           `json:"iscsi,omitempty"`
	MinIO                   MinIOConfig           `json:"minio,omitempty"`
	UPS                     UPSConfig             `json:"ups,omitempty"`
	DiskPower               DiskPowerConfig       `json:"disk_power,omitempty"`
	SystemPower             SystemPowerConfig     `json:"system_power,omitempty"`
	ActiveCertName          string                `json:"active_cert_name,omitempty"`
	PendingCertRestart      bool                  `json:"pending_cert_restart,omitempty"`
	SudoersHardeningEnabled bool                  `json:"sudoers_hardening_enabled,omitempty"`
	SudoersSilencedLines    []string              `json:"sudoers_silenced_lines,omitempty"`
	SudoersSilencedMissing  []string              `json:"sudoers_silenced_missing,omitempty"`
	SudoersSilencedExtra    []string              `json:"sudoers_silenced_extra,omitempty"`
	SudoersAppliedHash      string                `json:"sudoers_applied_hash,omitempty"`
	SudoersAppliedContent   string                `json:"sudoers_applied_content,omitempty"`
	Replication             []ReplicationTask     `json:"replication,omitempty"`
	InterLink               []LinkedServer        `json:"inter_link,omitempty"`
	InterlinkRelayMode      bool                  `json:"interlink_relay_mode,omitempty"`    // global relay mode: proxy API calls through local server
	LXDMetricsEnabled       bool                  `json:"lxd_metrics_enabled,omitempty"`     // turns on LXD's Prometheus endpoint on 127.0.0.1:9101 + portal scraper for VM/container Monitor tabs (v6.4.28)
	WebSession              WebSessionPolicy      `json:"web_session,omitempty"`             // browser session lifetime policy (default 24h vs sliding inactivity timeout)
	LXDSnapshotPolicies     []LXDSnapshotPolicy   `json:"lxd_snapshot_policies,omitempty"`   // v6.5.19 — per-instance scheduled snapshots
	ComposeUpdatePolicies   []ComposeUpdatePolicy `json:"compose_update_policies,omitempty"` // per-stack scheduled auto-updates
	LXDBackupPolicies       []LXDBackupPolicy     `json:"lxd_backup_policies,omitempty"`     // v6.5.19 — per-instance scheduled syncoid backups
	ExternalStorages        []ExternalStorage     `json:"external_storages,omitempty"`       // v6.7.7 — Filesystem rsync external storage targets
	MergerFS                MergerFSConfig        `json:"mergerfs,omitempty"`                // v6.7.13 — optional MergerFS union-filesystem support
	MergerFSSnapshotPolicies []MergerFSSnapshotPolicy `json:"mergerfs_snapshot_policies,omitempty"` // v6.7.13 — per-mergerfs coordinated ZFS snapshot schedules

	// ── Services (v6.8.1) ────────────────────────────────────────────────
	// The two default-ON switches are *pointers* on purpose: an absent key in
	// an existing config file must mean "enabled". A plain bool would decode
	// to false and silently disable the feature on every upgraded host.
	ServiceDiscoveryEnabled   *bool `json:"service_discovery_enabled,omitempty"`    // nil = on
	ServiceProxyEnabled       *bool `json:"service_proxy_enabled,omitempty"`        // nil = on
}

// ServiceDiscoveryOn reports whether service discovery is enabled. Absent =
// enabled, so existing configs keep the feature after an upgrade.
func (c *AppConfig) ServiceDiscoveryOn() bool {
	return c.ServiceDiscoveryEnabled == nil || *c.ServiceDiscoveryEnabled
}

// ServiceProxyOn reports whether the service proxy may serve. Disabling
// discovery disables the proxy too — it is the master switch (spec §2.6).
func (c *AppConfig) ServiceProxyOn() bool {
	if !c.ServiceDiscoveryOn() {
		return false
	}
	return c.ServiceProxyEnabled == nil || *c.ServiceProxyEnabled
}


// ── MergerFS (v6.7.13, optional feature) ─────────────────────────────────────

// MergerFSBranch is one source path in a mergerfs union. ZFSDataset is set when
// the path resolves to a ZFS dataset mountpoint (enables coordinated snapshots).
type MergerFSBranch struct {
	Path       string `json:"path"`
	ZFSDataset string `json:"zfs_dataset,omitempty"`
}

// MergerFSPool is one mergerfs union filesystem managed by ZNAS.
type MergerFSPool struct {
	Name             string           `json:"name"`              // logical name / tab label / default fsname
	Mountpoint       string           `json:"mountpoint"`        // union mount target (under /mnt or a zpool mountpoint)
	Branches         []MergerFSBranch `json:"branches"`
	CreatePolicy     string           `json:"create_policy"`     // mfs | epmfs | pfrd
	MinFreeSpace     string           `json:"minfreespace"`      // e.g. "50G"
	MoveOnENOSPC     bool             `json:"moveonenospc"`
	CacheFiles       string           `json:"cache_files"`       // off | partial | full | auto-full
	DropCacheOnClose bool             `json:"dropcacheonclose"`
	AllowOther       bool             `json:"allow_other"`
	InodeCalc        string           `json:"inodecalc"`         // path-hash | …
	FsName           string           `json:"fsname"`
	NoFail           bool             `json:"nofail"`
	AllZFS           bool             `json:"all_zfs"`           // cached: every branch is a ZFS dataset → global snapshots available
	ZFSCompression   string           `json:"zfs_compression,omitempty"` // when AllZFS: zfs compression applied to every member dataset ("" = leave as-is)
	CreatedAt        time.Time        `json:"created_at,omitempty"`
}

// MergerFSConfig holds all persistent MergerFS settings.
type MergerFSConfig struct {
	Enabled bool           `json:"enabled"`
	HideNav bool           `json:"hide_nav"`
	Pools   []MergerFSPool `json:"pools,omitempty"`
}

// MergerFSSnapshotPolicy schedules coordinated ZFS snapshots across all member
// datasets of an all-ZFS mergerfs. Mirrors LXDSnapshotPolicy's cadence fields.
type MergerFSSnapshotPolicy struct {
	Pool         string `json:"pool"`     // MergerFSPool.Name
	Enabled      bool   `json:"enabled"`
	EveryN       int    `json:"every_n"`
	Unit         string `json:"unit"` // "minute"|"hour"|"day"|"week"|"month"
	HourOfDay    int    `json:"hour_of_day,omitempty"`
	MinuteOfHour int    `json:"minute_of_hour"`
	Weekday      int    `json:"weekday,omitempty"`
	DayOfMonth   int    `json:"day_of_month,omitempty"`
	KeepLast     int    `json:"keep_last"`
	NamePrefix   string `json:"name_prefix,omitempty"`
	LastRun      time.Time `json:"last_run,omitempty"`
	LastStatus   string    `json:"last_status,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

// ExternalStorage describes one remote filesystem target for the Protect →
// Filesystem rsync tab (v6.7.7). All four protocols funnel into a local
// mount under /mnt/zfsnas-ext/<id>, then the file browser and rsync operate
// against that path.
type ExternalStorage struct {
	ID       string `json:"id"`   // short random id; also the mountpoint dir name
	Name     string `json:"name"` // display name
	Type     string `json:"type"` // "smb" | "nfs" | "ftp" | "ssh"
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`  // ftp/ssh only; 0 = protocol default
	Share    string `json:"share,omitempty"` // smb share name / nfs export path / ssh+ftp base path
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Domain   string `json:"domain,omitempty"`   // smb optional AD/workgroup domain
	SSHKey   bool   `json:"ssh_key,omitempty"`  // true = config/extstorage/<id>.key is used instead of Password
	// MountMode: "ondemand" (default — mounted for rsync runs / file-browser
	// use, auto-unmounted when idle) or "persistent" (mounted at save +
	// service startup, stays mounted). SSH/FTP are always on-demand.
	MountMode string `json:"mount_mode,omitempty"`
	ExtraOpts string `json:"extra_opts,omitempty"` // extra mount options (power users)

	Rsync *RsyncConfig `json:"rsync,omitempty"` // nil = sync not configured

	// Last rsync run state (updated after every run, incl. scheduled ones).
	LastSyncTime    time.Time `json:"last_sync_time,omitempty"`
	LastSyncStatus  string    `json:"last_sync_status,omitempty"` // "ok" | "error" | "paused" | ""
	LastSyncError   string    `json:"last_sync_error,omitempty"`
	LastSyncLog     string    `json:"last_sync_log,omitempty"` // tail of the last run's output
	LastSyncBytes   int64     `json:"last_sync_bytes,omitempty"`
	LastSyncSeconds int       `json:"last_sync_seconds,omitempty"`

	// Pause/resume state (v6.7.7 time-window + user-stop). A paused sync is
	// an interrupted-but-resumable run: rsync --partial continues where it
	// left off. The scheduler auto-restarts it at SyncResumeAt; a manual Run
	// always forces an immediate resume.
	SyncPaused      bool      `json:"sync_paused,omitempty"`
	SyncPauseReason string    `json:"sync_pause_reason,omitempty"` // "window" | "user"
	SyncResumeAt    time.Time `json:"sync_resume_at,omitempty"`    // zero = manual resume only
}

// RsyncConfig is the one synchronization job an ExternalStorage can carry.
type RsyncConfig struct {
	Enabled    bool   `json:"enabled"`
	Direction  string `json:"direction"`             // "pull" (remote→local) | "push" (local→remote)
	RemotePath string `json:"remote_path,omitempty"` // subpath inside the mount; "" = share root
	LocalPath  string `json:"local_path"`            // absolute local path (dataset directory)
	// Schedule — same shape as scheduler.Policy so IsDue/NextRun are reused.
	Frequency  string `json:"frequency"` // manual | hourly | daily | weekly | monthly
	Hour       int    `json:"hour"`
	Minute     int    `json:"minute"`
	Weekday    int    `json:"weekday,omitempty"`
	DayOfMonth int    `json:"day_of_month,omitempty"`
	// Options
	Delete     bool   `json:"delete,omitempty"`      // --delete (mirror deletions)
	MaxDelete  int    `json:"max_delete,omitempty"`  // --max-delete=N safety cap (0 = unlimited); only with Delete
	BWLimitKB  int    `json:"bwlimit_kb,omitempty"`  // --bwlimit=N (KB/s)
	ExtraFlags string `json:"extra_flags,omitempty"` // appended raw rsync flags
	// Optional daily run window ("HH:MM", both set = enabled; may wrap
	// midnight, e.g. 22:00→06:00). A sync still running at window close is
	// paused and auto-resumed at the next window open; a scheduled start
	// outside the window is deferred to the next open.
	WindowStart string `json:"window_start,omitempty"`
	WindowEnd   string `json:"window_end,omitempty"`
}

// WebSessionPolicy controls how long a browser-side login lasts and how it
// expires. Sessions are persisted to disk (encrypted) regardless of the
// chosen mode so they survive a server restart.
//   - Mode == "default":    session lasts 24 h from creation, no sliding window.
//   - Mode == "inactivity": session expires N minutes after the last
//     authenticated request. IdleTimeoutMinutes is clamped to [5, 10080]
//     (5 min .. 7 days) on save.
type WebSessionPolicy struct {
	Mode               string `json:"mode"`                 // "default" | "inactivity"
	IdleTimeoutMinutes int    `json:"idle_timeout_minutes"` // 5..10080, only used when Mode == "inactivity"
}

// WebSession bounds.
const (
	WebSessionModeDefault    = "default"
	WebSessionModeInactivity = "inactivity"
	WebSessionMinIdleMinutes = 5     // 5 minutes
	WebSessionMaxIdleMinutes = 10080 // 7 days
)

// NormaliseWebSession fills in defaults and clamps out-of-range values so
// callers can always trust the policy after a load. Called from
// LoadAppConfig and from the settings save path.
func NormaliseWebSession(p *WebSessionPolicy) {
	if p.Mode != WebSessionModeDefault && p.Mode != WebSessionModeInactivity {
		p.Mode = WebSessionModeDefault
	}
	if p.IdleTimeoutMinutes <= 0 {
		p.IdleTimeoutMinutes = 60
	}
	if p.IdleTimeoutMinutes < WebSessionMinIdleMinutes {
		p.IdleTimeoutMinutes = WebSessionMinIdleMinutes
	}
	if p.IdleTimeoutMinutes > WebSessionMaxIdleMinutes {
		p.IdleTimeoutMinutes = WebSessionMaxIdleMinutes
	}
}

// UserPreferences holds per-user UI preferences persisted across sessions.
type UserPreferences struct {
	ActivityBarCollapsed bool                `json:"activity_bar_collapsed,omitempty"`
	SelectedPool         string              `json:"selected_pool,omitempty"`          // last pool shown in Pool tab
	SelectedTopBarPool   string              `json:"selected_top_bar_pool,omitempty"`  // last pool shown in top bar
	Theme                string              `json:"theme,omitempty"`                  // UI theme name (dark, light, auto, tron, …)
	ThemeDay             string              `json:"theme_day,omitempty"`              // theme used by Auto during daytime
	ThemeNight           string              `json:"theme_night,omitempty"`            // theme used by Auto at night
	LandingPage          string              `json:"landing_page,omitempty"`           // page shown after login
	CapSelectedKeys      map[string][]string `json:"cap_selected_keys,omitempty"`      // capacity trend selection keyed by "local" or relay hostname
	TreemapSelectedDS    map[string]string   `json:"treemap_selected_ds,omitempty"`    // treemap selected pool/dataset keyed by "local" or relay hostname
	BottomTerminalHeight int                 `json:"bottom_terminal_height,omitempty"` // remembered pixel height of the bottom terminal panel; 0 = default
	LXDColumns           []string            `json:"lxd_columns,omitempty"`            // selected toggleable columns for VM/Container tables; nil = default set
	LXDGrouping          string              `json:"lxd_grouping,omitempty"`           // compute-tree grouping: "" | "none" | "tag" | "type"
	LXDGroupCollapsed    map[string][]string `json:"lxd_group_collapsed,omitempty"`    // collapsed compute-tree group ids keyed by "local" or relay hostname
	// Topology "Star / radial" placement: node positions the user pinned by
	// dragging. Outer key "<local|relay-host>:<storage|network>", inner key =
	// node id, value = [x, y] in map canvas coordinates.
	MapPins map[string]map[string][2]float64 `json:"map_pins,omitempty"`
}

// User represents a portal or SMB-only user.
type User struct {
	ID            string               `json:"id"`
	Username      string               `json:"username"`
	Email         string               `json:"email"`
	PasswordHash  string               `json:"password_hash"`
	Role          string               `json:"role"` // admin, read-only, smb-only
	CreatedAt     time.Time            `json:"created_at"`
	Preferences   UserPreferences      `json:"preferences,omitempty"`
	TOTPSecret    string               `json:"totp_secret,omitempty"`     // base32-encoded TOTP secret
	TOTPEnabled   bool                 `json:"totp_enabled,omitempty"`    // 2FA active
	SMBHomeFolder bool                 `json:"smb_home_folder,omitempty"` // home dir under SMBHomeDataset
	UID           *int                 `json:"uid,omitempty"`             // custom Linux UID (nil = auto)
	GID           *int                 `json:"gid,omitempty"`             // custom Linux GID (nil = auto)
	StandardPerms *StandardPermissions `json:"standard_perms,omitempty"`  // nil unless role == "standard"
}

// EncryptionKey is metadata for a stored ZFS encryption key file.
// The raw 32-byte key is stored separately in config/keys/<ID>.key.
type EncryptionKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// LoadEncryptionKeys loads all encryption key metadata from disk.
func LoadEncryptionKeys() ([]EncryptionKey, error) {
	var keys []EncryptionKey
	if err := loadJSON("encryption_keys.json", &keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []EncryptionKey{}
	}
	return keys, nil
}

// SaveEncryptionKeys persists encryption key metadata to disk.
func SaveEncryptionKeys(keys []EncryptionKey) error {
	return saveJSON("encryption_keys.json", keys)
}

var (
	configDir string
	mu        sync.RWMutex
	usersMu   sync.Mutex // serialises the full load→modify→save cycle for users.json
	totpKey   []byte     // AES-256 key for TOTP secret encryption
	chapKey   []byte     // AES-256 key for iSCSI CHAP credential encryption
	apiKeyKey []byte     // AES-256 key for API key encryption
)

// UpdateUserByID atomically loads users.json, calls fn with a pointer to the
// matching user, then saves the result. All under usersMu so concurrent writes
// cannot interleave and cause lost updates.
func UpdateUserByID(id string, fn func(*User) error) error {
	usersMu.Lock()
	defer usersMu.Unlock()
	users, err := LoadUsers()
	if err != nil {
		return err
	}
	user := FindUserByID(users, id)
	if user == nil {
		return fmt.Errorf("user not found")
	}
	if err := fn(user); err != nil {
		return err
	}
	return SaveUsers(users)
}

// LockUsers acquires the users-file mutex for a multi-step load→modify→save
// sequence that cannot be expressed as a single UpdateUserByID call.
// Caller must defer UnlockUsers() immediately after calling LockUsers().
func LockUsers()   { usersMu.Lock() }
func UnlockUsers() { usersMu.Unlock() }

// Init creates the config directory, stores its path, and loads encryption keys.
func Init(dir string) error {
	configDir = dir
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	if key, err := secret.LoadOrCreateKey(filepath.Join(dir, "totp.key")); err != nil {
		log.Printf("[config] warning: could not load/create TOTP key: %v — secrets stored unencrypted", err)
	} else {
		totpKey = key
	}
	if key, err := secret.LoadOrCreateKey(filepath.Join(dir, "chap.key")); err != nil {
		log.Printf("[config] warning: could not load/create CHAP key: %v — CHAP credentials stored unencrypted", err)
	} else {
		chapKey = key
	}
	if key, err := secret.LoadOrCreateKey(filepath.Join(dir, "api_keys.key")); err != nil {
		log.Printf("[config] warning: could not load/create API key encryption key: %v — API keys stored unencrypted", err)
	} else {
		apiKeyKey = key
	}
	return nil
}

// Dir returns the current config directory path.
func Dir() string {
	return configDir
}

func loadJSON(filename string, v interface{}) error {
	mu.RLock()
	defer mu.RUnlock()
	path := filepath.Join(configDir, filename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func saveJSON(filename string, v interface{}) error {
	mu.Lock()
	defer mu.Unlock()
	path := filepath.Join(configDir, filename)
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// Write atomically: write to a temp file then rename.
	// os.Rename is a POSIX atomic operation, so readers always see a complete file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// DockerDetectVMsOn reports the effective Docker-detection setting for VMs.
// Defaults ON when never explicitly configured (nil pointer); an explicit
// false is honoured.
func (c *AppConfig) DockerDetectVMsOn() bool {
	return c.DockerDetectVMs == nil || *c.DockerDetectVMs
}

// DockerDetectContainersOn is the same for LXC containers — defaults ON.
func (c *AppConfig) DockerDetectContainersOn() bool {
	return c.DockerDetectContainers == nil || *c.DockerDetectContainers
}

// LoadAppConfig loads or initializes application config with defaults.
func LoadAppConfig() (*AppConfig, error) {
	// Detect whether the config file already exists before loading, so we can
	// distinguish a fresh install (apply all defaults) from an existing config
	// that has WeeklyScrub explicitly set to false.
	fresh := false
	if _, err := os.Stat(filepath.Join(configDir, "config.json")); os.IsNotExist(err) {
		fresh = true
	}

	cfg := &AppConfig{Port: 8443}
	if err := loadJSON("config.json", cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = 8443
	}
	if cfg.StorageUnit == "" {
		cfg.StorageUnit = "gb"
	}
	if cfg.MaxSmbdProcesses == 0 {
		cfg.MaxSmbdProcesses = 100
	}
	NormaliseWebSession(&cfg.WebSession)
	if cfg.ISCSI.BaseName == "" {
		cfg.ISCSI.BaseName = "iqn.2003-06.ca.chezmoi.zfsnas"
	}
	if cfg.ISCSI.Port == 0 {
		cfg.ISCSI.Port = 3260
	}
	if cfg.ISCSI.Hosts == nil {
		cfg.ISCSI.Hosts = []ISCSIHost{}
	}
	if cfg.ISCSI.Shares == nil {
		cfg.ISCSI.Shares = []ISCSIShare{}
	}
	if cfg.ISCSI.Credentials == nil {
		cfg.ISCSI.Credentials = []ISCSICredential{}
	}
	if cfg.Replication == nil {
		cfg.Replication = []ReplicationTask{}
	}
	if cfg.InterLink == nil {
		cfg.InterLink = []LinkedServer{}
	}
	if fresh {
		// Fresh install: relay mode on by default (proxy API calls through
		// the local server so remote portals need not be browser-reachable).
		cfg.InterlinkRelayMode = true
	}
	if cfg.MinIO.Port == 0 {
		cfg.MinIO.Port = 9000
	}
	if cfg.MinIO.ConsolePort == 0 {
		cfg.MinIO.ConsolePort = 9001
	}
	if cfg.MinIO.Region == "" {
		cfg.MinIO.Region = "us-east-1"
	}
	if cfg.MinIO.RootUser == "" {
		cfg.MinIO.RootUser = "minioadmin"
	}
	if cfg.MinIO.Buckets == nil {
		cfg.MinIO.Buckets = []S3Bucket{}
	}
	// Migrate legacy WeeklyScrub bool to ScrubSchedule string.
	if cfg.ScrubSchedule == "" {
		if fresh {
			// Fresh install: default to weekly at 02:00
			cfg.ScrubSchedule = "weekly"
			cfg.ScrubHour = 2
		} else if cfg.WeeklyScrub {
			// Existing config with weekly scrub enabled → migrate
			cfg.ScrubSchedule = "weekly"
			cfg.ScrubHour = 2
		}
		// If WeeklyScrub was false, ScrubSchedule stays "" (off)
	}
	// Decrypt iSCSI CHAP credentials. Plaintext values (legacy) pass through unchanged.
	if chapKey != nil {
		for i := range cfg.ISCSI.Credentials {
			c := &cfg.ISCSI.Credentials[i]
			if secret.IsEncrypted(c.InPassword) {
				if plain, err := secret.Decrypt(chapKey, c.InPassword); err == nil {
					c.InPassword = plain
				}
			}
			if secret.IsEncrypted(c.OutPassword) {
				if plain, err := secret.Decrypt(chapKey, c.OutPassword); err == nil {
					c.OutPassword = plain
				}
			}
		}
	}
	return cfg, nil
}

// APIKeyEntry represents a named API key used by external integrations (e.g. homepage widget).
type APIKeyEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	// PoolTarget pins the homepage widget's single capacity metric to a
	// specific pool, encoded as "zfs:<name>" or "mergerfs:<name>". Empty =
	// default (the first zpool), so existing keys are unaffected.
	PoolTarget string `json:"pool_target,omitempty"`
}

// LoadAPIKeys loads all API keys from disk, decrypting key values if encrypted.
func LoadAPIKeys() ([]APIKeyEntry, error) {
	var keys []APIKeyEntry
	if err := loadJSON("api_keys.json", &keys); err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []APIKeyEntry{}
	}
	// Decrypt key values. Legacy plaintext keys pass through unchanged.
	if apiKeyKey != nil {
		for i := range keys {
			if secret.IsEncrypted(keys[i].Key) {
				if plain, err := secret.Decrypt(apiKeyKey, keys[i].Key); err == nil {
					keys[i].Key = plain
				}
			}
		}
	}
	return keys, nil
}

// SaveAPIKeys persists all API keys to disk, encrypting key values if a key is available.
func SaveAPIKeys(keys []APIKeyEntry) error {
	if apiKeyKey == nil {
		return saveJSON("api_keys.json", keys)
	}
	// Encrypt on a copy so we don't modify the caller's slice.
	toWrite := make([]APIKeyEntry, len(keys))
	copy(toWrite, keys)
	for i := range toWrite {
		k := toWrite[i].Key
		if k != "" && !secret.IsEncrypted(k) {
			if enc, err := secret.Encrypt(apiKeyKey, k); err == nil {
				toWrite[i].Key = enc
			}
		}
	}
	return saveJSON("api_keys.json", toWrite)
}

// SaveAppConfig persists application config, encrypting CHAP credentials if a key is available.
func SaveAppConfig(cfg *AppConfig) error {
	if chapKey == nil || len(cfg.ISCSI.Credentials) == 0 {
		return saveJSON("config.json", cfg)
	}
	// Encrypt on a deep copy so we don't modify the caller's config.
	cfgCopy := *cfg
	credsCopy := make([]ISCSICredential, len(cfg.ISCSI.Credentials))
	copy(credsCopy, cfg.ISCSI.Credentials)
	for i := range credsCopy {
		c := &credsCopy[i]
		if c.InPassword != "" && !secret.IsEncrypted(c.InPassword) {
			if enc, err := secret.Encrypt(chapKey, c.InPassword); err == nil {
				c.InPassword = enc
			}
		}
		if c.OutPassword != "" && !secret.IsEncrypted(c.OutPassword) {
			if enc, err := secret.Encrypt(chapKey, c.OutPassword); err == nil {
				c.OutPassword = enc
			}
		}
	}
	isciCopy := cfg.ISCSI
	isciCopy.Credentials = credsCopy
	cfgCopy.ISCSI = isciCopy
	return saveJSON("config.json", &cfgCopy)
}

// LoadUsers loads all users from disk, decrypting TOTP secrets if encrypted.
func LoadUsers() ([]User, error) {
	var users []User
	if err := loadJSON("users.json", &users); err != nil {
		return nil, err
	}
	if users == nil {
		users = []User{}
	}
	// Decrypt TOTP secrets. Legacy plaintext secrets are left as-is.
	if totpKey != nil {
		for i := range users {
			if secret.IsEncrypted(users[i].TOTPSecret) {
				if plain, err := secret.Decrypt(totpKey, users[i].TOTPSecret); err == nil {
					users[i].TOTPSecret = plain
				}
			}
		}
	}
	return users, nil
}

// SaveUsers persists all users to disk, encrypting TOTP secrets if a key is available.
func SaveUsers(users []User) error {
	if totpKey == nil {
		return saveJSON("users.json", users)
	}
	// Encrypt on a copy so we don't modify the caller's slice.
	toWrite := make([]User, len(users))
	copy(toWrite, users)
	for i := range toWrite {
		s := toWrite[i].TOTPSecret
		if s != "" && !secret.IsEncrypted(s) {
			if enc, err := secret.Encrypt(totpKey, s); err == nil {
				toWrite[i].TOTPSecret = enc
			}
		}
	}
	return saveJSON("users.json", toWrite)
}

// FindUserByUsername returns the user with the given username, or nil.
func FindUserByUsername(users []User, username string) *User {
	for i := range users {
		if users[i].Username == username {
			return &users[i]
		}
	}
	return nil
}

// FindUserByID returns the user with the given ID, or nil.
func FindUserByID(users []User, id string) *User {
	for i := range users {
		if users[i].ID == id {
			return &users[i]
		}
	}
	return nil
}
