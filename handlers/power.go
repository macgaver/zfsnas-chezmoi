package handlers

import (
	"net/http"
	"zfsnas/internal/audit"
	"zfsnas/system"
)

func HandleReboot(w http.ResponseWriter, r *http.Request) {
	if ApplianceImageWriteActive() {
		jsonErr(w, http.StatusConflict, "The appliance image is being written to the USB stick — rebooting now would leave it unbootable. Wait for the write to finish (Platform → USB Appliance Upgrades).")
		return
	}
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
	if ApplianceImageWriteActive() {
		jsonErr(w, http.StatusConflict, "The appliance image is being written to the USB stick — shutting down now would leave it unbootable. Wait for the write to finish (Platform → USB Appliance Upgrades).")
		return
	}
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

func HandleRestartPortal(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionSystemReboot,
		Target: "zfsnas-portal",
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]string{"message": "restarting portal"})
	system.RestartPortal()
}
