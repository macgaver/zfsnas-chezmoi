package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

// lxdCDROMResponse describes the CD/DVD drives currently attached to a VM and
// the ISOs available in the same storage pool — payload for the in-console
// drive picker.
//
// IsVM is the trigger the toolbar uses to decide whether to render the disc
// button at all: containers don't have a CDROM concept here, but every VM
// can have a CDROM attached on demand (e.g. mid-install driver injection),
// so the toolbar shows the button even when no ISO is currently inserted.
type lxdCDROMResponse struct {
	Configured []lxdCDROMEntry     `json:"configured"`
	Pool       string              `json:"pool"`
	Available  []system.LXDISOInfo `json:"available"`
	Running    bool                `json:"running"`
	IsVM       bool                `json:"is_vm"`
}

type lxdCDROMEntry struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
}

// HandleLXDListCDROMs returns the current CD/DVD drive configuration plus the
// ISOs available in the VM's storage pool. The VGA console toolbar uses this
// to populate its drive-swap menu.
// GET /api/lxd/instances/{name}/cdroms
func HandleLXDListCDROMs(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	cfg, err := system.LXDGetConfig(name)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}

	resp := lxdCDROMResponse{}
	for _, p := range cfg.CDROMs {
		if p == "" {
			continue
		}
		resp.Configured = append(resp.Configured, lxdCDROMEntry{
			Path:     p,
			Filename: filepath.Base(p),
		})
	}

	// Resolve the VM's root pool — it's the default destination for the swap
	// when the UI doesn't pass an explicit pool (e.g. clicking "Eject").
	for _, d := range cfg.Disks {
		if d.IsRoot && d.Pool != "" {
			resp.Pool = d.Pool
			break
		}
	}
	if resp.Pool == "" && len(cfg.Disks) > 0 {
		resp.Pool = cfg.Disks[0].Pool
	}

	// List ISOs from every Incus storage pool, not just the VM's root pool,
	// so the operator can attach an installer or driver disc that happens
	// to live on another local pool without having to copy it first.
	if isos, err := system.LXDListISOsAllPools(); err == nil {
		resp.Available = isos
	}
	if resp.Available == nil {
		resp.Available = []system.LXDISOInfo{}
	}
	if resp.Configured == nil {
		resp.Configured = []lxdCDROMEntry{}
	}

	if status, _ := system.LXDGetStatus(name); strings.EqualFold(status, "Running") {
		resp.Running = true
	}
	resp.IsVM = cfg.IsVM

	jsonOK(w, resp)
}

// HandleLXDSwapCDROM replaces the first CD/DVD drive with the named ISO,
// or detaches it when filename is empty. The pool field, if provided,
// selects which storage pool the ISO is read from — required now that
// the picker lists ISOs from every pool. When omitted (eject, legacy
// callers) it falls back to the VM's root pool.
// The VM must be restarted for the change to take effect — raw.qemu is
// consumed only at QEMU start.
// POST /api/lxd/instances/{name}/cdroms/swap
// body: {"filename": "ubuntu.iso", "pool": "tank"} or {"filename": ""}
func HandleLXDSwapCDROM(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	sess := MustSession(r)
	var req struct {
		Filename string `json:"filename"`
		Pool     string `json:"pool"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Filename = filepath.Base(strings.TrimSpace(req.Filename))
	if req.Filename == "." || req.Filename == "/" {
		req.Filename = ""
	}

	cfg, err := system.LXDGetConfig(name)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}

	pool := strings.TrimSpace(req.Pool)
	if pool == "" {
		for _, d := range cfg.Disks {
			if d.IsRoot && d.Pool != "" {
				pool = d.Pool
				break
			}
		}
		if pool == "" && len(cfg.Disks) > 0 {
			pool = cfg.Disks[0].Pool
		}
	}
	if pool == "" {
		jsonErr(w, http.StatusBadRequest, "could not resolve storage pool for VM")
		return
	}

	// Build the new CDROM list: replace slot 0 with the chosen ISO (or empty),
	// keep any additional slots untouched. Resolve via the unified pool
	// helper so we accept either an Incus storage pool or a raw ZFS pool
	// — the picker can list ISOs from any pool the host can see.
	var newPaths []string
	if req.Filename != "" {
		p, err := system.LXDResolveISOPath(pool, req.Filename)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "cannot resolve ISO: "+err.Error())
			return
		}
		newPaths = append(newPaths, p)
	} else {
		newPaths = append(newPaths, "")
	}
	for i, p := range cfg.CDROMs {
		if i == 0 {
			continue
		}
		newPaths = append(newPaths, p)
	}

	cfg.CDROMs = newPaths
	cfg.ApplyCDROMs = true
	// cfg came from LXDGetConfig (full config), so applying the scalar section
	// is a no-op re-write of current values — set the gate so behaviour is
	// unchanged for the CDROM-swap path.
	cfg.ManageResources = true
	if err := system.LXDSetConfig(name, cfg); err != nil {
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDEditConfig, Target: name, Result: audit.ResultError, Details: "cdrom swap: " + err.Error()})
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	target := req.Filename
	if target == "" {
		target = "(empty)"
	} else {
		target = pool + "/" + target
	}
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionLXDEditConfig, Target: name, Result: audit.ResultOK, Details: "cdrom → " + target})

	running := false
	if status, _ := system.LXDGetStatus(name); strings.EqualFold(status, "Running") {
		running = true
	}
	jsonOK(w, map[string]interface{}{
		"ok":      true,
		"running": running,
	})
}
