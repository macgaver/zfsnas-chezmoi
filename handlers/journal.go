package handlers

import (
	"net/http"
	"strconv"

	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleJournalAvailable reports whether the journal tabs should be shown in the
// Activity & Events page. The tabs require (a) passwordless sudo for journalctl
// and (b) an admin session — raw system logs are sensitive, so non-admins never
// see them. The `incus` flag drives the optional "Virtualization Services" tab
// and `samba` the optional "Samba" tab.
//
// Returns available=false (rather than 403) for non-admins so the frontend can
// simply hide the tabs without special-casing the error.
func HandleJournalAvailable(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	admin := sess.Role == config.RoleAdmin
	avail := admin && system.JournalAvailable()
	jsonOK(w, map[string]bool{
		"available": avail,
		"incus":     avail && system.IncusInstalled(),
		"samba":     avail && system.IsSambaInstalled(),
	})
}

// HandleJournal returns the last N journal entries for the requested source.
// Query params:
//
//	kind  — one of kernel | zfsnas | samba | incus | all  (default kernel)
//	lines — 100..500, clamped                     (default 100)
//
// Admin-only (registered behind RequireAdmin in the router).
func HandleJournal(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "kernel"
	}

	lines := 25
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	if lines < 1 {
		lines = 25
	}
	if lines > 500 {
		lines = 500
	}

	// prio: 0..7 = filter to that severity or more severe (journalctl -p);
	// anything else (incl. empty / "all") = no level filter.
	maxPrio := -1
	if v := r.URL.Query().Get("prio"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxPrio = n
		}
	}

	if !system.JournalAvailable() {
		jsonErr(w, http.StatusServiceUnavailable, "journalctl is not available (sudo grant missing)")
		return
	}

	entries, err := system.ReadJournal(kind, lines, maxPrio)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"kind":    kind,
		"lines":   lines,
		"entries": entries,
	})
}
