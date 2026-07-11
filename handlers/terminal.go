package handlers

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"zfsnas/internal/session"
	"zfsnas/internal/termsessions"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var termUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser clients (curl, etc.)
		}
		return strings.HasSuffix(origin, "://"+r.Host)
	},
}

// HandleTerminal opens a WebSocket attached to the user's host-shell
// terminal session. When the query string carries ?session_id=<uuid> we
// reattach to that existing PTY (replaying its scrollback); otherwise we
// create a new session via termsessions.New. WS disconnect now DETACHES
// — the PTY keeps running until the user explicitly closes it or their
// web session expires.
func HandleTerminal(w http.ResponseWriter, r *http.Request) {
	conn, err := termUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sess := MustSession(r)
	wsAttachOrCreate(conn, r, sess.UserID, termsessions.KindHost, "", "Host shell", func() (*exec.Cmd, *os.File, error) {
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
		cmd := exec.Command(shell)
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
		ptmx, err := pty.Start(cmd)
		return cmd, ptmx, err
	})
}

// HandleUpdaterTerminal opens a WebSocket attached to an INTERACTIVE OS-update
// session: a PTY that runs `apt-get update` then `apt-get dist-upgrade` with the
// user free to answer apt's prompts (conffile diffs, "continue? [Y/n]"), then
// drops to a shell so the output stays on screen. This is the hands-on
// counterpart to the streamed, unattended "Auto Update" (/ws/updates-apply).
// Same persistent-session machinery as the host shell, so a dropped browser can
// reattach and keep watching the upgrade.
func HandleUpdaterTerminal(w http.ResponseWriter, r *http.Request) {
	conn, err := termUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sess := MustSession(r)
	wsAttachOrCreate(conn, r, sess.UserID, termsessions.KindUpdater, "", "OS Update", func() (*exec.Cmd, *os.File, error) {
		// sudo is NOPASSWD-allowed for apt-get (ZFSNAS_APT alias). dist-upgrade
		// without -y keeps it interactive. The script ENDS when apt finishes (no
		// trailing shell) so the PTY closes and the session terminates on its own
		// — same as typing `exit` right after the upgrade.
		const script = `set +e
printf '\n\033[1;36m=== Interactive OS Update ===\033[0m\n\n'
printf '\033[1;33m> sudo apt-get update\033[0m\n'
sudo apt-get update
printf '\n\033[1;33m> sudo apt-get dist-upgrade\033[0m\n'
sudo apt-get dist-upgrade
printf '\n\033[1;32m=== Update session finished. ===\033[0m\n'`
		cmd := exec.Command("/bin/bash", "-c", script)
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
		ptmx, err := pty.Start(cmd)
		return cmd, ptmx, err
	})
}

// wsSessionKeepalive marks the owning web session active for as long as a
// long-lived WebSocket stays open. Auth middleware only Touch()es the
// session on each HTTP request, and a WS authenticates exactly once at
// upgrade — so a client that just holds a terminal open without polling the
// REST API (the iOS app; the SPA polls constantly and never hits this) looks
// idle to the "inactivity" web-session mode and gets evicted after
// IdleTimeoutMinutes (default 60), which kills every PTY the user owns
// mid-use. Returns a stop func; call it when the WS detaches so a closed
// terminal stops counting as activity.
func wsSessionKeepalive(token string) func() {
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				session.Default.Touch(token)
			case <-stop:
				return
			}
		}
	}()
	return func() { close(stop) }
}

// wsAttachOrCreate is the shared "find existing session or spawn a new
// one, then run the attach loop" used by every PTY-backed WS handler.
// Ownership is enforced — a session_id from another user is rejected.
// First text frame sent back to the client is a one-line JSON envelope
// with the session ID so the UI can persist it and tag the tab.
func wsAttachOrCreate(ws *websocket.Conn, r *http.Request,
	userID, kind, target, title string,
	spawn termsessions.SpawnFunc) {

	store := termsessions.Default
	id := r.URL.Query().Get("session_id")
	var ts *termsessions.Session
	reattach := false
	if id != "" {
		ts = store.Get(id)
		if ts == nil || ts.UserID() != userID {
			ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"session not found"}`)) //nolint:errcheck
			return
		}
		reattach = true
	} else {
		// A client opening a SECOND session for the same target passes its own
		// suffixed label (e.g. "buildserver216 (1)") via ?title= so every window
		// shows the same name (v6.6.11). Falls back to the handler's default.
		if t := r.URL.Query().Get("title"); t != "" {
			title = t
		}
		var err error
		ts, err = store.New(userID, kind, target, title, spawn)
		if err != nil {
			ws.WriteMessage(websocket.TextMessage,
				[]byte(`{"type":"error","error":"failed to start: `+jsonEscape(err.Error())+`"}`)) //nolint:errcheck
			return
		}
	}
	// Initial envelope so the client learns its session ID.
	envelope := `{"type":"session","id":"` + ts.ID() + `","kind":"` + kind + `","reattach":` + boolJSON(reattach) + `}`
	ws.WriteMessage(websocket.TextMessage, []byte(envelope)) //nolint:errcheck

	// Pick up cols/rows from the query string if provided (the JS opens
	// the socket with ?cols=N&rows=M so the very first resize matches the
	// container before any data flows).
	cols := parseUint16(r.URL.Query().Get("cols"))
	rows := parseUint16(r.URL.Query().Get("rows"))

	// An attached terminal counts as user activity — keep the web session
	// alive for the duration or the inactivity evictor kills this very PTY.
	stopKeepalive := wsSessionKeepalive(MustSession(r).Token)
	defer stopKeepalive()

	// window_id identifies the browser window so multiple windows (even the same
	// user from different computers) can each be a viewer, with one controller.
	// The label ("<ip> · <browser>") is surfaced in the UI so the user can see
	// WHO holds a terminal when a control transfer happens.
	store.Attach(ts, ws, cols, rows, r.URL.Query().Get("window_id"), viewerLabel(r))
}

// viewerLabel builds a short "who is this" string from the request: the client
// IP plus a coarse browser/OS name parsed from the User-Agent.
func viewerLabel(r *http.Request) string {
	ip := clientIP(r)
	b := browserName(r.UserAgent())
	switch {
	case ip != "" && b != "":
		return ip + " · " + b
	case b != "":
		return b
	default:
		return ip
	}
}

// browserName returns a coarse browser/device name from a User-Agent string.
func browserName(ua string) string {
	switch {
	case ua == "":
		return ""
	case strings.Contains(ua, "iPad"):
		return "Safari · iPad"
	case strings.Contains(ua, "iPhone"):
		return "Safari · iPhone"
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera"):
		return "Opera"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Chrome/"):
		if strings.Contains(ua, "Android") {
			return "Chrome · Android"
		}
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	default:
		return "browser"
	}
}

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func jsonEscape(s string) string {
	// Minimal escape for the inline envelope strings — backslashes + quotes.
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func parseUint16(s string) uint16 {
	if s == "" {
		return 0
	}
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
		if n > 65535 {
			return 0
		}
	}
	return uint16(n)
}
