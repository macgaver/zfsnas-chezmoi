package handlers

// Firewall export/import (.znasfw) — one password-encrypted file holding the
// whole feature configuration. Import never applies by itself: it loads the
// (device-remapped) config into the draft, and the admin presses Apply.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/backup"
	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/internal/version"
	"zfsnas/system"
)

type sdnPendingImportEntry struct {
	file *sdn.ExportFile
	at   time.Time
}

var (
	sdnImportsMu sync.Mutex
	sdnImports   = map[string]sdnPendingImportEntry{}
)

// HandleSDNExport — POST /api/sdn/export {password} → .znasfw download
func HandleSDNExport(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		host := system.GetHostname()
		data, err := sdn.Export(c, sdn.ExportFile{ZNASVersion: version.Version, Hostname: host, CreatedAt: time.Now().UTC()}, body.Password)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		name := "znas-firewall-" + safeName(host) + "-" + time.Now().Format("20060102-1504") + ".znasfw"
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write(data)
	}
}

// HandleSDNImportInspect — POST /api/sdn/import/inspect (multipart: file, password)
func HandleSDNImportInspect(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
		f, _, err := r.FormFile("file")
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "no file uploaded")
			return
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		ef, err := sdn.Import(data, r.FormValue("password"))
		if errors.Is(err, backup.ErrBadPassword) || errors.Is(err, sdn.ErrNotSDNExport) || errors.Is(err, backup.ErrNotBackup) {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		live := system.SDNDeviceNames()
		have := map[string]bool{}
		for _, d := range live {
			have[d] = true
		}
		missing := []string{}
		for _, d := range sdn.DevicesNeeded(ef.Config) {
			if !have[d] {
				missing = append(missing, d)
			}
		}
		cur, _ := sdnStoreFor(appCfg).LoadConfirmed()
		id := sdn.NewID()
		sdnImportsMu.Lock()
		for k, v := range sdnImports { // abandoned inspections expire
			if time.Since(v.at) > time.Hour {
				delete(sdnImports, k)
			}
		}
		sdnImports[id] = sdnPendingImportEntry{file: ef, at: time.Now()}
		sdnImportsMu.Unlock()
		jsonOK(w, map[string]any{
			"id": id, "hostname": ef.Hostname, "znas_version": ef.ZNASVersion, "created_at": ef.CreatedAt,
			"summary": sdn.Summarize(cur, ef.Config), "devices_needed": sdn.DevicesNeeded(ef.Config),
			"devices_missing": missing, "live_devices": live,
		})
	}
}

// HandleSDNImportApply — POST /api/sdn/import/apply {id, mapping} → draft
func HandleSDNImportApply(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID      string            `json:"id"`
			Mapping map[string]string `json:"mapping"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		sdnImportsMu.Lock()
		ent, ok := sdnImports[body.ID]
		delete(sdnImports, body.ID)
		sdnImportsMu.Unlock()
		if !ok {
			jsonErr(w, http.StatusNotFound, "this import has expired — upload the file again")
			return
		}
		sess := MustSession(r)
		c := sdn.RemapDevices(ent.file.Config, body.Mapping)
		sdnMu.Lock()
		defer sdnMu.Unlock()
		st := sdnStoreFor(appCfg)
		d, err := st.LoadDraft()
		if err == nil {
			d, err = st.SaveDraft(c, d.Revision, sess.Username)
		}
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNImport, Target: "firewall",
			Result: audit.ResultOK, Details: "loaded into draft from " + ent.file.Hostname})
		jsonOK(w, sdnDraftView(st, d))
	}
}
