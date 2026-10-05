// Configuration backup & migration (export / import of the whole ZNAS setup).
// Plan: PLANS/plan-config-backup-migration.md.
//
//	POST /api/backup/export          admin — password + options → .znasbak download
//	POST /api/backup/inspect         admin, or anyone while the server has NO users
//	                                 (first-run /setup) — file + password → plan
//	POST /api/backup/apply           same rule — import_id + choices → job id
//	GET  /api/backup/jobs/{id}       same rule — job progress
//	POST /api/backup/rollback        admin — restore the pre-import settings copy
package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/internal/backup"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/internal/version"
	"zfsnas/system"
)

// ── what goes in ──────────────────────────────────────────────────────────

// Never exported: machine-local caches, logs of local daemons, the session
// key (everyone signs in again after an import), and our own rollback copies.
var backupSkipNames = map[string]bool{
	"session.key": true, "sessions.json.enc": true, // login sessions never travel
	"smart_cache.json": true, "updates_cache.json": true,
	"lxc.log": true, "qemu.log": true,
}
var backupSkipDirs = map[string]bool{"folder_usage": true, "lxd_metrics": true}

// config.json keys that describe THIS machine; on import the target keeps its
// own values (port, sudoers state, relay mode, caches…).
var backupLocalConfigKeys = []string{
	"port", "bind_port_443", "smart_last_refresh", "version_check_cache",
	"pending_cert_restart", "sudoers_hardening_enabled", "sudoers_silenced_lines",
	"sudoers_silenced_missing", "sudoers_silenced_extra", "sudoers_applied_hash",
	"sudoers_applied_content", "interlink_relay_mode",
}

// Rollback copies live INSIDE the config dir (persisted on the appliance,
// where siblings of it sit on the RAM-backed OS layer). Export and the copy
// itself skip them.
const preImportPrefix = ".pre-import-"

type backupExportReq struct {
	Password      string `json:"password"`
	IncludeCharts bool   `json:"include_charts"`
	IncludeAudit  bool   `json:"include_audit"`
	IncludeCerts  bool   `json:"include_certs"`
}

// HandleBackupExport streams an encrypted backup of this server's configuration.
func HandleBackupExport(w http.ResponseWriter, r *http.Request) {
	var req backupExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if len(req.Password) < backup.MinPasswordLen {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("the password must be at least %d characters", backup.MinPasswordLen))
		return
	}
	opts := backup.ExportOptions{IncludeCharts: req.IncludeCharts, IncludeAudit: req.IncludeAudit,
		IncludeCerts: req.IncludeCerts, IncludeHostname: true}
	m, files, err := buildBackup(opts)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	arch, err := backup.Build(m, files)
	if err == nil {
		arch, err = backup.Seal(req.Password, arch)
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "could not build the backup: "+err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: "config-backup-export", Result: audit.ResultOK,
		Details: fmt.Sprintf("%d users, %d pools, %d instances, %d KB", len(m.Inventory.Users), len(m.Inventory.Pools),
			len(m.Inventory.Instances), len(arch)/1024)})
	name := fmt.Sprintf("znas-backup-%s-%s.znasbak", safeName(m.Hostname), time.Now().Format("20060102-1504"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(arch)
}

func safeName(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "znas"
	}
	return b.String()
}

// buildBackup gathers the files and the manifest.
func buildBackup(opts backup.ExportOptions) (backup.Manifest, map[string][]byte, error) {
	files := map[string][]byte{}
	dir := config.Dir()
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if fi.IsDir() {
			if backupSkipDirs[top] || strings.HasPrefix(top, preImportPrefix) || strings.HasPrefix(fi.Name(), ".") ||
				(top == "certs" && !opts.IncludeCerts) {
				return filepath.SkipDir
			}
			return nil
		}
		name := fi.Name()
		switch {
		case !fi.Mode().IsRegular(), backupSkipNames[name], strings.HasSuffix(name, ".tmp"):
			return nil
		case name == "audit.log" && !opts.IncludeAudit:
			return nil
		case strings.HasSuffix(name, ".rrd.json") && !opts.IncludeCharts:
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		files["config/"+filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return backup.Manifest{}, nil, err
	}

	m := backup.Manifest{ZNASVersion: version.Version, SourceType: "host", Hostname: system.GetHostname(),
		CreatedAt: time.Now().UTC(), Options: opts}
	if system.ApplianceMode() {
		m.SourceType = "appliance"
	}
	inv := &m.Inventory

	users, _ := config.LoadUsers()
	var names []string
	for _, u := range users {
		names = append(names, u.Username)
	}
	inv.Users = names
	accts, warns := system.ExportLinuxAccounts(names)
	inv.Warnings = append(inv.Warnings, warns...)
	inv.Accounts = len(accts)
	files["system/accounts.json"], _ = json.MarshalIndent(accts, "", "  ")
	if smb, err := system.ExportSMBHashes(names); err == nil {
		files["system/smbpasswd"] = []byte(smb)
		inv.SMBPassword = strings.Count(smb, "\n")
	} else {
		inv.Warnings = append(inv.Warnings, "SMB passwords could not be read ("+err.Error()+"); users will set them again after the import")
	}
	files["system/hostname"] = []byte(system.GetHostname() + "\n")

	var smbShares []system.SMBShare
	_ = json.Unmarshal(files["config/shares.json"], &smbShares)
	for _, s := range smbShares {
		inv.SMBShares = append(inv.SMBShares, s.Name)
	}
	var nfsShares []system.NFSShare
	_ = json.Unmarshal(files["config/nfs-shares.json"], &nfsShares)
	for _, s := range nfsShares {
		inv.NFSExports = append(inv.NFSExports, s.Path)
	}
	if cfg, err := config.LoadAppConfig(); err == nil {
		inv.ISCSI = len(cfg.ISCSI.Shares)
		if inv.ISCSI > 0 {
			inv.Features = append(inv.Features, "iscsi")
		}
		if cfg.UPS.Enabled {
			inv.Features = append(inv.Features, "ups")
		}
		if len(cfg.MergerFS.Pools) > 0 {
			inv.Features = append(inv.Features, "mergerfs")
		}
		if cfg.MinIO.Enabled {
			inv.Features = append(inv.Features, "s3")
		}
	}
	guids := system.PoolGUIDs()
	for name, g := range guids {
		inv.Pools = append(inv.Pools, backup.PoolRef{Name: name, GUID: g})
	}
	sort.Slice(inv.Pools, func(i, j int) bool { return inv.Pools[i].Name < inv.Pools[j].Name })

	if system.LXDAvailable() {
		incus, err := system.ExportIncusInventory()
		if err != nil {
			inv.Warnings = append(inv.Warnings, "VMs & containers could not be listed: "+err.Error())
		}
		if len(incus.Storage) > 0 || len(incus.Instances) > 0 {
			inv.Features = append(inv.Features, "virtualization")
			files["incus/inventory.json"], _ = json.MarshalIndent(incus, "", "  ")
			nets := map[string]bool{}
			for _, s := range incus.Storage {
				inv.Datastores = append(inv.Datastores, backup.DatastoreRef{Name: s.Name, Driver: s.Driver, Source: s.Source})
			}
			for _, in := range incus.Instances {
				ref := backup.InstanceRef{Name: in.Name, Type: in.Type, Pool: in.Pool}
				for _, n := range in.NICs {
					att := n.Network
					if att == "" {
						att = n.Parent
					}
					if att != "" {
						ref.Networks = append(ref.Networks, att)
						nets[att] = true
					}
				}
				inv.Instances = append(inv.Instances, ref)
			}
			for n := range nets {
				inv.Networks = append(inv.Networks, n)
			}
			sort.Strings(inv.Networks)
		}
	}
	return m, files, nil
}

// ── import: inspect ──────────────────────────────────────────────────────

type pendingImport struct {
	manifest backup.Manifest
	files    map[string][]byte
	created  time.Time
	setup    bool // started from first-run /setup (no users existed)
}

var (
	importsMu sync.Mutex
	imports   = map[string]*pendingImport{}
	jobs      = map[string]*importJob{}
)

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// backupImportAllowed: an admin, or anyone while the server has no users at
// all (the first-run /setup window — the same rule /api/auth/setup uses).
func backupImportAllowed(r *http.Request) (setup bool, ok bool) {
	if users, _ := config.LoadUsers(); len(users) == 0 {
		return true, true
	}
	sess, ok := SessionFromRequest(r)
	return false, ok && sess.Role == config.RoleAdmin
}

// ImportPlan is what the wizard shows before anything changes.
type ImportPlan struct {
	ImportID   string          `json:"import_id"`
	Manifest   backup.Manifest `json:"manifest"`
	Setup      bool            `json:"setup"`
	Hostname   string          `json:"hostname"` // this server's
	Pools      []planPool      `json:"pools"`
	Accounts   []planAccount   `json:"accounts"`
	VirtHere   bool            `json:"virt_here"`
	Missing    []string        `json:"missing_features"`
	Networks   []planNetwork   `json:"networks"`
	Bridges    []string        `json:"bridges"` // bridges available here for mapping
	ForceNeeds bool            `json:"force_needed"`
}

type planPool struct {
	Name  string `json:"name"`
	GUID  string `json:"guid"`
	State string `json:"state"` // imported | importable | foreign | missing
	Note  string `json:"note"`
}

type planAccount struct {
	Name     string `json:"name"`
	UID      int    `json:"uid"`
	Conflict string `json:"conflict,omitempty"`
}

type planNetwork struct {
	Name    string `json:"name"`
	Managed bool   `json:"managed"` // a managed network in the backup (can be recreated)
	Exists  bool   `json:"exists"`  // already here
	Suggest string `json:"suggest"` // proposed mapping when missing
}

// HandleBackupInspect decrypts an uploaded backup and returns the import plan.
func HandleBackupInspect(w http.ResponseWriter, r *http.Request) {
	setup, ok := backupImportAllowed(r)
	if !ok {
		jsonErr(w, http.StatusForbidden, "admin rights required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, backup.MaxFileSize+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, http.StatusBadRequest, "upload failed: "+err.Error())
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "no backup file uploaded")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, backup.MaxFileSize+1))
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "upload failed")
		return
	}
	plain, err := backup.Open(r.FormValue("password"), data)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	m, files, err := backup.Extract(plain)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id := randomID()
	importsMu.Lock()
	for k, p := range imports { // drop stale ones
		if time.Since(p.created) > 30*time.Minute {
			delete(imports, k)
		}
	}
	imports[id] = &pendingImport{manifest: m, files: files, created: time.Now(), setup: setup}
	importsMu.Unlock()
	jsonOK(w, buildPlan(id, m, files, setup))
}

func buildPlan(id string, m backup.Manifest, files map[string][]byte, setup bool) ImportPlan {
	p := ImportPlan{ImportID: id, Manifest: m, Setup: setup, Hostname: system.GetHostname(),
		VirtHere: system.LXDAvailable(), Bridges: system.HostBridgeNames()}
	here := system.PoolGUIDs()
	hereByGUID := map[string]string{}
	for n, g := range here {
		hereByGUID[g] = n
	}
	importable, _ := system.DetectImportablePools()
	impByGUID := map[string]system.ImportablePool{}
	for _, ip := range importable {
		impByGUID[ip.ID] = ip
	}
	for _, pr := range m.Inventory.Pools {
		pp := planPool{Name: pr.Name, GUID: pr.GUID}
		switch {
		case hereByGUID[pr.GUID] != "":
			pp.State, pp.Note = "imported", "already imported here"
		case impByGUID[pr.GUID].ID != "":
			pp.State = "importable"
			pp.Note = "disks found — will be imported"
			p.ForceNeeds = true // moved disks: almost always last used by the old server
		default:
			pp.State, pp.Note = "missing", "disks not found — connect them, then check again"
		}
		p.Pools = append(p.Pools, pp)
	}
	var accts []system.LinuxAccount
	_ = json.Unmarshal(files["system/accounts.json"], &accts)
	for _, a := range accts {
		p.Accounts = append(p.Accounts, planAccount{Name: a.Name, UID: a.UID, Conflict: system.AccountConflict(a)})
	}
	for _, f := range m.Inventory.Features {
		if !featureInstalledHere(f) {
			p.Missing = append(p.Missing, f)
		}
	}
	var incus system.IncusInventory
	_ = json.Unmarshal(files["incus/inventory.json"], &incus)
	managed := map[string]bool{}
	for _, n := range incus.Networks {
		managed[n.Name] = true
	}
	def := ""
	for _, b := range p.Bridges {
		if b == "vmbr0" {
			def = b
		}
	}
	if def == "" && len(p.Bridges) > 0 {
		def = p.Bridges[0]
	}
	for _, n := range m.Inventory.Networks {
		pn := planNetwork{Name: n, Managed: managed[n]}
		pn.Exists = system.IncusNetworkExists(n) || contains(p.Bridges, n)
		if !pn.Exists && !pn.Managed {
			pn.Suggest = def
		}
		p.Networks = append(p.Networks, pn)
	}
	return p
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func featureInstalledHere(f string) bool {
	switch f {
	case "iscsi":
		return system.ISCSIPrereqsInstalled()
	case "ups":
		return system.UPSPrereqsInstalled()
	case "mergerfs":
		return system.MergerFSInstalled()
	case "s3":
		return system.MinIOPrereqsInstalled()
	case "virtualization":
		return system.LXDAvailable()
	}
	return true
}

// ── import: apply (background job) ───────────────────────────────────────

type importJob struct {
	mu      sync.Mutex
	Lines   []string `json:"lines"`
	Done    bool     `json:"done"`
	Failed  bool     `json:"failed"`
	Error   string   `json:"error,omitempty"`
	Summary []string `json:"summary"` // things the admin should know / do next
	setup   bool
}

func (j *importJob) logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	log.Printf("[backup-import] %s", msg)
	j.mu.Lock()
	j.Lines = append(j.Lines, msg)
	j.mu.Unlock()
}
func (j *importJob) note(format string, a ...any) {
	j.mu.Lock()
	j.Summary = append(j.Summary, fmt.Sprintf(format, a...))
	j.mu.Unlock()
}

type applyReq struct {
	ImportID        string            `json:"import_id"`
	ForceImport     bool              `json:"force_import"`
	RestoreHostname bool              `json:"restore_hostname"`
	NetworkMap      map[string]string `json:"network_map"` // backup network/bridge → bridge here
}

// HandleBackupApply starts the import job.
func HandleBackupApply(w http.ResponseWriter, r *http.Request) {
	setup, ok := backupImportAllowed(r)
	if !ok {
		jsonErr(w, http.StatusForbidden, "admin rights required")
		return
	}
	var req applyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	importsMu.Lock()
	pi := imports[req.ImportID]
	delete(imports, req.ImportID) // one use
	importsMu.Unlock()
	if pi == nil {
		jsonErr(w, http.StatusBadRequest, "this backup is no longer loaded — upload it again")
		return
	}
	if pi.setup && !setup {
		jsonErr(w, http.StatusConflict, "an account was created meanwhile — start the import again from Settings")
		return
	}
	job := &importJob{setup: setup}
	id := randomID()
	importsMu.Lock()
	jobs[id] = job
	importsMu.Unlock()
	user, role := "setup", "admin"
	if sess, ok := SessionFromRequest(r); ok {
		user, role = sess.Username, sess.Role
	}
	go runImport(job, pi, req, user, role)
	jsonOK(w, map[string]string{"job_id": id})
}

// HandleBackupJob reports an import job's progress. The job id is the
// capability (unguessable, returned only to whoever started it).
func HandleBackupJob(w http.ResponseWriter, r *http.Request) {
	importsMu.Lock()
	j := jobs[mux.Vars(r)["id"]]
	importsMu.Unlock()
	if j == nil {
		jsonErr(w, http.StatusNotFound, "no such import")
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	jsonOK(w, map[string]any{"lines": j.Lines, "done": j.Done, "failed": j.Failed, "error": j.Error, "summary": j.Summary})
}

func runImport(j *importJob, pi *pendingImport, req applyReq, user, role string) {
	fail := func(step string, err error) {
		j.logf("✗ %s: %v", step, err)
		j.mu.Lock()
		j.Done, j.Failed, j.Error = true, true, step+": "+err.Error()
		j.mu.Unlock()
		audit.Log(audit.Entry{User: user, Role: role, Action: "config-backup-import", Result: audit.ResultError,
			Details: "from " + pi.manifest.Hostname + ": " + step + ": " + err.Error()})
	}
	m, files := pi.manifest, pi.files
	j.logf("Importing the configuration of %s (ZNAS %s, %s)", m.Hostname, m.ZNASVersion, m.SourceType)

	// 1. Safety copy of the current settings.
	dir := config.Dir()
	snap := filepath.Join(dir, preImportPrefix+time.Now().Format("20060102-150405"))
	if err := copyDir(dir, snap); err != nil {
		fail("saving the current settings", err)
		return
	}
	j.logf("✓ Current settings saved (Settings → Backup & Migration → Roll back undoes the import)")
	_ = snap

	// 2. Settings files.
	if err := writeConfigFiles(dir, files, m.Options.IncludeCerts); err != nil {
		fail("writing the settings", err)
		return
	}
	j.logf("✓ Settings restored")

	// 3. Linux accounts (same uid/gid so file ownership on the pools stays right).
	var accts []system.LinuxAccount
	_ = json.Unmarshal(files["system/accounts.json"], &accts)
	for _, a := range accts {
		if err := system.RestoreLinuxAccount(a); err != nil {
			j.logf("! account %s: %v", a.Name, err)
			j.note("Account %q was not created: %v", a.Name, err)
			continue
		}
		j.logf("✓ Account %s (uid %d)", a.Name, a.UID)
	}
	// 4. SMB passwords.
	if smb := string(files["system/smbpasswd"]); strings.TrimSpace(smb) != "" {
		done, err := system.ImportSMBHashes(smb)
		if len(done) > 0 {
			j.logf("✓ SMB passwords restored (%s)", strings.Join(done, ", "))
		}
		if err != nil {
			j.logf("! SMB passwords: %v", err)
			j.note("Some SMB passwords could not be restored (%v): set them again in Settings → Users", err)
		}
	}

	// 5. ZFS pools.
	here := system.PoolGUIDs()
	hereByGUID := map[string]bool{}
	for _, g := range here {
		hereByGUID[g] = true
	}
	importable := map[string]bool{}
	if list, err := system.DetectImportablePools(); err == nil {
		for _, ip := range list {
			importable[ip.ID] = true
		}
	}
	for _, p := range m.Inventory.Pools {
		if hereByGUID[p.GUID] {
			j.logf("✓ Pool %s already imported", p.Name)
			continue
		}
		if !importable[p.GUID] {
			j.logf("– pool %s: disks not found, skipped", p.Name)
			j.note("Pool %q was not found: connect its disks, then use Import ZFS Pool on the Pools page; its shares and VMs are already configured", p.Name)
			continue
		}
		j.logf("… importing pool %s", p.Name)
		if err := system.ImportPoolByGUID(p.GUID, req.ForceImport); err != nil {
			j.logf("! pool %s: %v", p.Name, err)
			j.note("Pool %q was not imported: %v", p.Name, err)
			continue
		}
		j.logf("✓ Pool %s imported", p.Name)
	}

	// 6. Shares.
	var smbShares []system.SMBShare
	if json.Unmarshal(files["config/shares.json"], &smbShares) == nil && len(smbShares) > 0 {
		if err := system.SaveSMBShares(dir, smbShares); err != nil {
			j.logf("! SMB shares: %v", err)
			j.note("SMB shares need attention: %v", err)
		} else {
			j.logf("✓ %d SMB share(s) applied", len(smbShares))
		}
	}
	var nfsShares []system.NFSShare
	if json.Unmarshal(files["config/nfs-shares.json"], &nfsShares) == nil && len(nfsShares) > 0 {
		if err := system.SaveNFSShares(dir, nfsShares); err != nil {
			j.logf("! NFS exports: %v", err)
			j.note("NFS exports need attention: %v", err)
		} else {
			j.logf("✓ %d NFS export(s) applied", len(nfsShares))
		}
	}
	if cfg, err := config.LoadAppConfig(); err == nil && len(cfg.ISCSI.Shares) > 0 {
		if !system.ISCSIPrereqsInstalled() {
			j.note("iSCSI is not installed here: install it from Requisites → Optional Features, its %d target(s) will then be applied", len(cfg.ISCSI.Shares))
		} else if err := system.ApplyISCSIConfig(&cfg.ISCSI); err != nil {
			j.logf("! iSCSI: %v", err)
			j.note("iSCSI targets need attention: %v", err)
		} else {
			j.logf("✓ %d iSCSI target(s) applied", len(cfg.ISCSI.Shares))
		}
	}

	if cfg, err := config.LoadAppConfig(); err == nil {
		if len(cfg.MergerFS.Pools) > 0 {
			if !system.MergerFSInstalled() {
				j.note("MergerFS is not installed here: install it from Requisites → Optional Features, then recreate its %d pool(s)", len(cfg.MergerFS.Pools))
			} else {
				for _, mp := range cfg.MergerFS.Pools {
					if _, err := system.CreateMergerFS(mp); err != nil {
						j.logf("! MergerFS %s: %v", mp.Name, err)
						j.note("MergerFS pool %q needs attention: %v", mp.Name, err)
					} else {
						j.logf("✓ MergerFS %s mounted", mp.Name)
					}
				}
			}
		}
		if cfg.UPS.Enabled {
			j.note("UPS settings were restored: open the UPS panel and click Save once to apply them to this machine")
		}
	}

	// 7. VMs & containers.
	importIncus(j, files, req.NetworkMap)

	// 8. Hostname.
	if req.RestoreHostname {
		if hn := strings.TrimSpace(string(files["system/hostname"])); hn != "" && hn != system.GetHostname() {
			if err := system.SetHostname(hn); err != nil {
				j.logf("! hostname: %v", err)
			} else {
				j.logf("✓ Hostname set to %s", hn)
			}
		}
	}

	audit.Log(audit.Entry{User: user, Role: role, Action: "config-backup-import", Result: audit.ResultOK,
		Details: fmt.Sprintf("from %s (ZNAS %s, %s)", m.Hostname, m.ZNASVersion, m.SourceType)})
	j.logf("✓ Import finished — the portal restarts now. Sign in with your migrated account.")
	j.mu.Lock()
	j.Done = true
	j.mu.Unlock()
	// The users were replaced: nobody keeps a session (or a role) issued
	// before the import.
	session.Default.DeleteAll("config_import")
	// Let the wizard read the final state, then restart so every part of the
	// portal (schedulers, encryption-key loading, MergerFS, UPS…) starts from
	// the imported settings.
	time.AfterFunc(4*time.Second, system.RestartPortal)
}

func importIncus(j *importJob, files map[string][]byte, netMap map[string]string) {
	var inv system.IncusInventory
	if err := json.Unmarshal(files["incus/inventory.json"], &inv); err != nil || (len(inv.Storage) == 0 && len(inv.Instances) == 0) {
		return
	}
	if !system.LXDAvailable() {
		j.note("The backup has %d VM(s)/container(s), but virtualization is not enabled here: enable it in Requisites → Optional Features, then use Settings → Backup & Migration → Import again", len(inv.Instances))
		return
	}
	// Networks first: recreated profiles may reference them.
	for _, n := range inv.Networks {
		if netMap[n.Name] != "" || system.IncusNetworkExists(n.Name) {
			continue
		}
		if err := system.CreateIncusNetworkFromBackup(n); err != nil {
			j.logf("! network %s: %v", n.Name, err)
		} else {
			j.logf("✓ Network %s recreated", n.Name)
		}
	}
	for _, p := range inv.Profiles {
		if !system.IncusProfileExists(p.Name) {
			if err := system.CreateIncusProfileFromBackup(p); err != nil {
				j.logf("! profile %s: %v", p.Name, err)
			} else {
				j.logf("✓ Profile %s recreated", p.Name)
			}
		}
	}
	j.logf("… looking for VMs & containers on the datastores")
	res, err := system.IncusRecover(inv.Storage, true)
	if err != nil {
		j.logf("! VMs & containers: %v", err)
		j.note("VMs & containers were not recovered: %v", err)
		return
	}
	if len(res.DependencyErrors) > 0 {
		j.logf("! VMs & containers need: %s", strings.Join(res.DependencyErrors, "; "))
		j.note("VMs & containers were not recovered because something they need is missing: %s", strings.Join(res.DependencyErrors, "; "))
		return
	}
	if len(res.UnknownVolumes) == 0 {
		j.logf("✓ VMs & containers already registered here")
		return
	}
	j.logf("✓ %d VM(s)/container(s) and volume(s) recovered", len(res.UnknownVolumes))
	// Point NICs at the bridges chosen for networks that do not exist here.
	for _, in := range inv.Instances {
		for dev, nic := range in.NICs {
			key := nic.Network
			if key == "" {
				key = nic.Parent
			}
			to := netMap[key]
			if to == "" || to == key {
				continue
			}
			mapped := system.NICRef{Parent: to}
			if system.IncusNetworkExists(to) && !contains(system.HostBridgeNames(), to) {
				mapped = system.NICRef{Network: to}
			}
			if err := system.RemapInstanceNIC(in.Name, dev, mapped); err != nil {
				j.logf("! %s/%s → %s: %v", in.Name, dev, to, err)
			} else {
				j.logf("✓ %s: %s now on %s", in.Name, dev, to)
			}
		}
	}
	j.note("VMs & containers are back but stopped — start them from VMs & Containers when you are ready")
}

// writeConfigFiles writes the backup's config/ files into dir. config.json is
// merged so this machine keeps its own host-specific keys.
func writeConfigFiles(dir string, files map[string][]byte, withCerts bool) error {
	var names []string
	for n := range files {
		if strings.HasPrefix(n, "config/") {
			names = append(names, n)
		}
	}
	sort.Slice(names, func(i, k int) bool { // key files first, then the JSON they unlock
		return strings.HasSuffix(names[i], ".key") && !strings.HasSuffix(names[k], ".key")
	})
	for _, n := range names {
		rel := strings.TrimPrefix(n, "config/")
		data := files[n]
		if rel == "config.json" {
			merged, err := mergeLocalConfig(filepath.Join(dir, "config.json"), data, withCerts)
			if err != nil {
				return err
			}
			data = merged
		}
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		if !strings.HasPrefix(dst, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("refusing path %q", n)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0750); err != nil {
			return err
		}
		tmp := dst + ".import-tmp"
		if err := os.WriteFile(tmp, data, 0600); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
	}
	return nil
}

// mergeLocalConfig keeps this machine's values for backupLocalConfigKeys
// (and its active certificate when the backup carries no certificates).
func mergeLocalConfig(localPath string, incoming []byte, withCerts bool) ([]byte, error) {
	var in map[string]json.RawMessage
	if err := json.Unmarshal(incoming, &in); err != nil {
		return nil, fmt.Errorf("config.json in the backup is unreadable: %w", err)
	}
	local := map[string]json.RawMessage{}
	if b, err := os.ReadFile(localPath); err == nil {
		_ = json.Unmarshal(b, &local)
	}
	keys := append([]string(nil), backupLocalConfigKeys...)
	if !withCerts {
		keys = append(keys, "active_cert_name")
	}
	for _, k := range keys {
		if v, ok := local[k]; ok {
			in[k] = v
		} else {
			delete(in, k)
		}
	}
	return json.MarshalIndent(in, "", "  ")
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			if rel != "." && (strings.HasPrefix(fi.Name(), preImportPrefix) || p == dst) {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0750)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, fi.Mode().Perm())
	})
}

// HandleBackupRollback restores the most recent pre-import settings copy.
func HandleBackupRollback(w http.ResponseWriter, r *http.Request) {
	dir := config.Dir()
	ents, _ := os.ReadDir(dir)
	latest := ""
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), preImportPrefix) && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		jsonErr(w, http.StatusNotFound, "no pre-import settings copy found")
		return
	}
	if err := restoreSnapshot(dir, filepath.Join(dir, latest)); err != nil {
		jsonErr(w, http.StatusInternalServerError, "rollback failed: "+err.Error())
		return
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: "config-backup-rollback", Result: audit.ResultOK, Details: latest})
	session.Default.DeleteAll("config_rollback")
	jsonOK(w, map[string]string{"restored": strings.TrimPrefix(latest, preImportPrefix)})
	time.AfterFunc(2*time.Second, system.RestartPortal)
}

// restoreSnapshot puts a pre-import copy back: its files overwrite the
// current ones, and settings files the import added (.json at the top level,
// e.g. users.json on a server that had none) are removed. Key material
// (keys/, certs/, *.key) is kept: an imported pool's encrypted datasets must
// stay unlockable after a rollback.
func restoreSnapshot(dir, snap string) error {
	// The live session key/store stay: everyone is signed out anyway, and a
	// key swapped under the running portal would make its shutdown flush
	// unreadable.
	err := filepath.Walk(snap, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(snap, p)
		target := filepath.Join(dir, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0750)
		}
		if !fi.Mode().IsRegular() || (filepath.Dir(rel) == "." && backupSkipNames[fi.Name()]) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, fi.Mode().Perm())
	})
	if err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") || backupSkipNames[n] {
			continue
		}
		if _, err := os.Stat(filepath.Join(snap, n)); os.IsNotExist(err) {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				return err
			}
		}
	}
	return nil
}

// HandleBackupStatus tells the Settings card whether a rollback copy exists.
func HandleBackupStatus(w http.ResponseWriter, r *http.Request) {
	ents, _ := os.ReadDir(config.Dir())
	latest := ""
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), preImportPrefix) && e.Name() > latest {
			latest = e.Name()
		}
	}
	jsonOK(w, map[string]any{"rollback_available": latest != "", "rollback_from": strings.TrimPrefix(latest, preImportPrefix)})
}
