package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"zfsnas/internal/audit"
	"zfsnas/internal/certgen"
	"zfsnas/internal/config"

	"github.com/gorilla/mux"
)

var validCertName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-]{0,38}$`)

// HandleListCerts returns all cert pairs in config/certs/.
// GET /api/certs
func HandleListCerts(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		certsDir := filepath.Join(appCfg.ConfigDir, "certs")
		certs, err := certgen.ListCerts(certsDir, appCfg.ActiveCertName)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]interface{}{
			"certs":           certs,
			"active_cert":     appCfg.ActiveCertName,
			"pending_restart": appCfg.PendingCertRestart,
		})
	}
}

// HandleUploadCert accepts a multipart form with name, cert_file, key_file.
// POST /api/certs/upload
func HandleUploadCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			jsonErr(w, http.StatusBadRequest, "failed to parse form")
			return
		}

		name := r.FormValue("name")
		if !validCertName.MatchString(name) {
			jsonErr(w, http.StatusBadRequest, "name must be alphanumeric with dashes (max 40 chars)")
			return
		}
		if name == "self-signed" {
			jsonErr(w, http.StatusBadRequest, "cannot replace the built-in self-signed certificate")
			return
		}

		certFile, _, err := r.FormFile("cert_file")
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "cert_file is required")
			return
		}
		defer certFile.Close()

		keyFile, _, err := r.FormFile("key_file")
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "key_file is required")
			return
		}
		defer keyFile.Close()

		// Read the whole part — a single Read() can short-read a multipart file
		// that spilled to a temp file, silently importing a truncated cert/key.
		certBytes, err := io.ReadAll(certFile)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "failed to read cert_file")
			return
		}
		keyBytes, err := io.ReadAll(keyFile)
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "failed to read key_file")
			return
		}

		certsDir := filepath.Join(appCfg.ConfigDir, "certs")
		if err := certgen.ImportCert(certsDir, name, certBytes, keyBytes); err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}

		certs, _ := certgen.ListCerts(certsDir, appCfg.ActiveCertName)
		var info interface{}
		for _, c := range certs {
			if c.Name == name {
				info = c
				break
			}
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Target:  "cert:" + name,
			Details: "certificate imported",
		})

		jsonOK(w, map[string]interface{}{"cert": info, "message": "Certificate imported successfully — pair is valid."})
	}
}

// HandleDeleteCert removes a cert pair from config/certs/.
// DELETE /api/certs/{name}
func HandleDeleteCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]

		activeName := appCfg.ActiveCertName
		if activeName == "" {
			activeName = "self-signed"
		}
		if name == activeName {
			jsonErr(w, http.StatusConflict, "cannot delete the active certificate")
			return
		}
		if name == "self-signed" {
			jsonErr(w, http.StatusBadRequest, "cannot delete the built-in self-signed certificate")
			return
		}

		certsDir := filepath.Join(appCfg.ConfigDir, "certs")
		os.Remove(filepath.Join(certsDir, name+".crt"))
		os.Remove(filepath.Join(certsDir, name+".key"))

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Target:  "cert:" + name,
			Details: "certificate deleted",
		})

		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleExportCert returns a zip archive of the cert + key.
// GET /api/certs/{name}/export
func HandleExportCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		certsDir := filepath.Join(appCfg.ConfigDir, "certs")
		data, err := certgen.ExportCertZip(certsDir, name)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, name))
		w.Write(data)
	}
}

// HandleActivateCert sets the active certificate.
// POST /api/certs/{name}/activate
func HandleActivateCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := mux.Vars(r)["name"]
		certsDir := filepath.Join(appCfg.ConfigDir, "certs")

		// Validate the cert exists and the pair is valid
		certs, err := certgen.ListCerts(certsDir, appCfg.ActiveCertName)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		var found *certgen.CertInfo
		for i := range certs {
			if certs[i].Name == name {
				found = &certs[i]
				break
			}
		}
		if found == nil {
			jsonErr(w, http.StatusNotFound, "certificate not found")
			return
		}
		if !found.IsValid {
			jsonErr(w, http.StatusBadRequest, "certificate pair is not valid")
			return
		}

		appCfg.ActiveCertName = name
		appCfg.PendingCertRestart = true
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Target:  "cert:" + name,
			Details: "certificate activated",
		})

		jsonOK(w, map[string]interface{}{"ok": true, "pending_restart": true})
	}
}

// HandleCertRestart restarts the portal process so the new certificate takes effect.
// POST /api/certs/restart
func HandleCertRestart(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appCfg.PendingCertRestart = false
		config.SaveAppConfig(appCfg)

		sess := MustSession(r)
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionUpdateSettings,
			Result:  audit.ResultOK,
			Target:  "cert-restart",
			Details: "portal restarting to apply new certificate",
		})

		// Respond before exiting so the client gets a response.
		jsonOK(w, map[string]string{"message": "restarting"})

		// Flush and exit — systemd Restart=on-failure triggers on non-zero exit.
		go func() {
			os.Exit(1)
		}()
	}
}
