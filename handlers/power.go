package handlers

import (
	"net/http"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

func HandleReboot(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionSystemReboot,
		Target: "server",
		Result: audit.ResultOK,
	})
	if err := system.Reboot(); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "rebooting"})
}

func HandleShutdown(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionSystemShutdown,
		Target: "server",
		Result: audit.ResultOK,
	})
	if err := system.Shutdown(); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "shutting down"})
}
