package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"zfsnas/internal/audit"
	"zfsnas/system"
)

// HandleSwappinessStatus returns the current vm.swappiness plus the live swap
// picture that gives it meaning.
func HandleSwappinessStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.GetSwappinessStatus())
}

// HandleSetSwappiness applies and persists a new value.
//
// The range is enforced here as well as in system.SetSwappiness: the slider is
// a convenience, not the trust boundary.
func HandleSetSwappiness(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value *int `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Value == nil {
		jsonErr(w, http.StatusBadRequest, "expected {\"value\": 0..100}")
		return
	}
	if err := system.SetSwappiness(*body.Value); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditSwappiness(r, *body.Value)
	jsonOK(w, system.GetSwappinessStatus())
}

func auditSwappiness(r *http.Request, v int) {
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: fmt.Sprintf("vm.swappiness set to %d (recommended %d)", v, system.RecommendedSwappiness),
	})
}
