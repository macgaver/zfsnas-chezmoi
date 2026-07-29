// Package termsessions implements persistent PTY-backed terminal sessions
// for ZNAS v6.5.30+. A Session keeps its PTY alive across WebSocket
// disconnects so the user can close the browser, come back, and resume the
// same shell. Lifetime is bounded by:
//   1. PTY EOF (target process exits — VM reboot, `exit` typed, etc.)
//   2. Explicit Terminate (user clicks the "x" on a tab)
//   3. TerminateUser (web session evicted — idle timeout, logout, hard cap)
//
// Server restarts are NOT survived — PTYs are kernel resources owned by
// the ZNAS process; a restart wipes them all. This is a documented limit
// (see PLANS/plan-version-6.5.30.md).
package termsessions

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// oscQueryRe matches OSC sequences that ask the terminal to REPORT something:
// they carry a "?" before the BEL or ST terminator — e.g. a background-colour
// query "\x1b]11;?\x07" (also foreground ]10, cursor ]12, palette ]4;N).
var oscQueryRe = regexp.MustCompile("\x1b\\][0-9;]*\\?(\x07|\x1b\\\\)")

// csiQueries are exact CSI report-requests (cursor position, device status,
// device attributes) that, like the OSC colour queries, make the terminal
// answer back.
var csiQueries = [][]byte{
	[]byte("\x1b[6n"), []byte("\x1b[5n"),
	[]byte("\x1b[c"), []byte("\x1b[0c"),
	[]byte("\x1b[>c"), []byte("\x1b[>0c"), []byte("\x1b[=c"),
}

// stripScrollbackQueries removes terminal-report REQUESTS from replayed
// scrollback. A program (vim, a prompt, dircolors…) may have queried the
// terminal's colours/cursor while running; those query bytes are invisible but
// get stored in the scrollback ring. On reconnect we replay the ring, the
// client's emulator re-answers the query, and the answer ("\x1b]11;rgb:fafa/
// fafa/fafa\x07") is injected into the shell at the prompt — where readline
// renders the printable part as garbage like "11;rgb:fafa/fafa/fafa". Dropping
// the queries from the replay (only) prevents the spurious re-answer without
// changing anything the user sees.
func stripScrollbackQueries(b []byte) []byte {
	if !bytes.Contains(b, []byte{0x1b}) {
		return b
	}
	b = oscQueryRe.ReplaceAll(b, nil)
	for _, q := range csiQueries {
		if bytes.Contains(b, q) {
			b = bytes.ReplaceAll(b, q, nil)
		}
	}
	return b
}

// Session reason constants — passed to Terminate / surfaced in the final
// scrollback line so the UI can render an honest reason.
const (
	ReasonProcessExit   = "process_exit"     // PTY EOF (VM down, exit typed, host shell quit)
	ReasonUserClose     = "user_close"       // explicit close from the UI
	ReasonSessionExpire = "session_expired"  // web session evicted
	ReasonReplaced      = "replaced_by_new"  // (unused today, reserved)
	ReasonShutdown      = "server_shutdown"
)

// Kind constants — descriptive label only; nothing in this package branches
// on them. Handlers use them so the UI can render an icon.
const (
	KindHost    = "host"    // /ws/terminal
	KindLXD     = "lxd"     // /ws/lxd-console
	KindCompose = "compose" // /ws/compose-console
	KindDocker  = "docker"  // /ws/docker-console
	KindUpdater = "updater" // /ws/updater — interactive OS package upgrade
)

// SpawnFunc returns a started *exec.Cmd and its controlling PTY. Sessions
// call this exactly once at New() time.
type SpawnFunc func() (*exec.Cmd, *os.File, error)

// Snapshot is the lightweight, copy-safe view of a session — what the
// list-sessions API returns and what the UI binds to.
type Snapshot struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	Kind       string    `json:"kind"`
	Target     string    `json:"target"`
	Title      string    `json:"title"`
	CreatedAt  time.Time `json:"created_at"`
	LastActive time.Time `json:"last_active"`
	Terminated bool      `json:"terminated"`
	TermReason string    `json:"term_reason,omitempty"`
	Attached   bool      `json:"attached"`
	Cols       uint16    `json:"cols"`
	Rows       uint16    `json:"rows"`
	// ControllerWindow is the windowID of the browser window currently driving
	// input (empty = no controller). ViewerCount is how many windows are
	// attached (mirrors + controller). Lets a freshly-opened window paint the
	// right dot before its own control frame arrives. (v6.6.11)
	ControllerWindow string `json:"controller_window,omitempty"`
	ControllerLabel  string `json:"controller_label,omitempty"` // "<ip> · <browser>" of the controlling window
	ViewerCount      int    `json:"viewer_count"`
}

// viewer is one attached browser window. Many viewers can mirror a session's
// output simultaneously; exactly one — the session's `controller` — has its
// keystrokes forwarded to the PTY. (v6.6.11)
type viewer struct {
	ws         *websocket.Conn
	writeMu    sync.Mutex // gorilla/websocket requires a single writer per conn
	windowID   string     // the browser window/page this viewer belongs to
	label      string     // "<ip> · <browser>" — shown as "who controls this" in the UI
	cols, rows uint16     // this viewer's reported size (PTY follows the controller's)
}

// write is the serialized per-viewer WebSocket write.
func (v *viewer) write(messageType int, data []byte) error {
	v.writeMu.Lock()
	defer v.writeMu.Unlock()
	return v.ws.WriteMessage(messageType, data)
}

// Session owns one PTY + its scrollback ring + the set of attached viewers.
type Session struct {
	id, userID, kind, target, title string
	createdAt                       time.Time

	mu          sync.Mutex
	lastActive  time.Time
	ptmx        *os.File
	cmd         *exec.Cmd
	scrollback  *ringBuf
	viewers     map[*viewer]struct{} // every attached browser window (mirrors + controller)
	controller  *viewer              // the viewer whose input reaches the PTY (nil ⇒ uncontrolled)
	cols, rows  uint16               // PTY geometry — tracks the controller's viewport
	terminated  bool
	termReason  string
	evictedTimer *time.Timer
}

// broadcast writes the same frame to EVERY attached viewer (each via its own
// write mutex). This is how the PTY output mirrors to all windows. A viewer
// whose write fails is dropped — its read loop will error out and detach too.
func (sess *Session) broadcast(messageType int, data []byte) {
	sess.mu.Lock()
	vs := make([]*viewer, 0, len(sess.viewers))
	for v := range sess.viewers {
		vs = append(vs, v)
	}
	sess.mu.Unlock()
	for _, v := range vs {
		if err := v.write(messageType, data); err != nil {
			sess.removeViewer(v)
		}
	}
}

// removeViewer detaches v from the session. If it was the controller, the
// session goes uncontrolled and the remaining viewers are told (dots → blue),
// so the next viewer to press Enter can claim it.
func (sess *Session) removeViewer(v *viewer) {
	sess.mu.Lock()
	if _, ok := sess.viewers[v]; !ok {
		sess.mu.Unlock()
		return
	}
	delete(sess.viewers, v)
	wasController := sess.controller == v
	if wasController {
		sess.controller = nil
	}
	sess.mu.Unlock()
	if wasController {
		sess.pushControlToAll()
	}
}

// takeControl promotes v to controller (demoting the previous one) and pushes
// the new control state to every viewer so their dots flip. The PTY is resized
// to the new controller's viewport.
func (sess *Session) takeControl(v *viewer) {
	sess.mu.Lock()
	if sess.terminated || sess.controller == v {
		sess.mu.Unlock()
		return
	}
	sess.controller = v
	if v.cols > 0 && v.rows > 0 {
		sess.cols, sess.rows = v.cols, v.rows
	}
	ptmx, c, r := sess.ptmx, sess.cols, sess.rows
	sess.mu.Unlock()
	if c > 0 && r > 0 {
		pty.Setsize(ptmx, &pty.Winsize{Cols: c, Rows: r}) //nolint:errcheck
	}
	sess.pushControlToAll()
}

// releaseControl drops v's controller role (no-op if it isn't the controller),
// leaving the session uncontrolled until someone else takes it. A window calls
// this for tabs it's no longer focused on, so its non-active tabs go blue and
// stay available to the windows actually using them. (v6.6.11)
func (sess *Session) releaseControl(v *viewer) {
	sess.mu.Lock()
	if sess.controller != v {
		sess.mu.Unlock()
		return
	}
	sess.controller = nil
	sess.mu.Unlock()
	sess.pushControlToAll()
}

// pushControlToAll sends each viewer a {"type":"control",...} frame describing
// whether IT is the controller and which window (+ a human label: ip · browser)
// currently holds control.
func (sess *Session) pushControlToAll() {
	sess.mu.Lock()
	vs := make([]*viewer, 0, len(sess.viewers))
	for v := range sess.viewers {
		vs = append(vs, v)
	}
	ctl := sess.controller
	by, byLabel := "", ""
	if ctl != nil {
		by, byLabel = ctl.windowID, ctl.label
	}
	sess.mu.Unlock()
	for _, v := range vs {
		v.write(websocket.TextMessage, controlFrame(v == ctl, by, byLabel)) //nolint:errcheck
	}
}

func controlFrame(isController bool, by, byLabel string) []byte {
	b, _ := json.Marshal(map[string]any{"type": "control", "controller": isController, "by": by, "by_label": byLabel})
	return b
}

// ctrlMsgType returns the "type" of a control JSON frame ("" if not one).
func ctrlMsgType(data []byte) string {
	if len(data) == 0 || data[0] != '{' {
		return ""
	}
	var m struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	return m.Type
}

// Store is the per-process session registry.
type Store struct {
	mu            sync.Mutex
	sessions      map[string]*Session
	scrollbackKB  int // 256 by default
	maxPerUser    int // 20 by default
}

// Default is the global store; main.go configures it at startup.
var Default = &Store{
	sessions:     make(map[string]*Session),
	scrollbackKB: 256,
	maxPerUser:   20,
}

// Configure sets the per-session ring buffer size (in KB) and the per-user
// session cap. Pass 0 to keep the existing default for either.
func (s *Store) Configure(scrollbackKB, maxPerUser int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if scrollbackKB > 0 {
		s.scrollbackKB = scrollbackKB
	}
	if maxPerUser > 0 {
		s.maxPerUser = maxPerUser
	}
}

// New creates a session and starts the PTY via spawn(). Returns the new
// session (already in the store, but not yet attached to a WebSocket).
func (s *Store) New(userID, kind, target, title string, spawn SpawnFunc) (*Session, error) {
	s.mu.Lock()
	cap := s.scrollbackKB * 1024
	maxPerUser := s.maxPerUser
	s.mu.Unlock()

	// Enforce per-user cap by soft-evicting the oldest detached session.
	s.enforceUserCap(userID, maxPerUser)

	cmd, ptmx, err := spawn()
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, 12)
	rand.Read(idBytes) //nolint:errcheck
	now := time.Now()
	sess := &Session{
		id:         hex.EncodeToString(idBytes),
		userID:     userID,
		kind:       kind,
		target:     target,
		title:      title,
		createdAt:  now,
		lastActive: now,
		ptmx:       ptmx,
		cmd:        cmd,
		scrollback: newRingBuf(cap),
		cols:       80,
		rows:       24,
	}

	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()

	// Start the PTY → scrollback drain. This runs for the life of the PTY
	// regardless of whether anyone is attached; the same goroutine also
	// fans out to the currently-attached WebSocket if there is one.
	go s.drainPTY(sess)

	return sess, nil
}

// drainPTY is the long-lived goroutine: read PTY → append to ring → maybe
// fan out to current WS. Exits on PTY EOF/error, after which it marks the
// session terminated and schedules eviction.
func (s *Store) drainPTY(sess *Session) {
	// Reap the child. markTerminated only Kill()s it, and a killed process
	// that is never Wait()ed stays <defunct> for the life of the daemon —
	// Go installs no SIGCHLD handler. Those PIDs count against the unit's
	// TasksMax, and once that fills, every fork the service makes starts
	// failing with EAGAIN: pty.Start() for a new terminal, and the `incus`
	// probes too. This is the single exit path for all five PTY kinds, and
	// ptmx.Close() always unblocks the Read above, so it covers every
	// termination route (process exit, user close, cap eviction, shutdown).
	defer func() {
		if sess.cmd != nil {
			sess.cmd.Wait() //nolint:errcheck
		}
	}()
	buf := make([]byte, 4096)
	for {
		n, err := sess.ptmx.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			sess.mu.Lock()
			sess.scrollback.Write(chunk) //nolint:errcheck
			sess.lastActive = time.Now()
			sess.mu.Unlock()
			sess.broadcast(websocket.BinaryMessage, chunk)
		}
		if err != nil {
			s.markTerminated(sess, ReasonProcessExit)
			return
		}
	}
}

// endedFrame is the structured "session ended" message the UI turns into a
// single "[…closed — press Enter to start a new session]" line (instead of a
// raw "[session ended]" text notice that lived in the scrollback and got
// replayed in a loop on every reconnect).
//
// It is sent as type:"error" ON PURPOSE so that ANY client — including one that
// predates the dedicated handling, or a stale browser window loaded before an
// upgrade — renders it as a readable "[error: …]" line rather than dumping the
// raw JSON. The ended:true flag + reason let an updated client recognise it,
// show the clean closed-notice, stop the reconnect loop, and offer Enter to
// start a new session. The notice text contains no " or \, so it embeds in JSON
// without escaping. reason is one of the Reason* constants.
func endedFrame(reason string) []byte {
	return []byte(`{"type":"error","ended":true,"reason":"` + reason + `","error":"` + closedNoticeText(reason) + `"}`)
}

// closedNoticeText is the human-readable one-liner for a closed session, also
// used as the fallback text older clients display.
func closedNoticeText(reason string) string {
	switch reason {
	case ReasonUserClose:
		return "This terminal session was closed from another window. Press Enter to start a new session."
	case ReasonProcessExit:
		return "This terminal session ended (the shell or process exited). Press Enter to start a new session."
	case ReasonSessionExpire:
		return "This terminal session expired. Press Enter to start a new session."
	case ReasonShutdown:
		return "This terminal session ended (the server restarted). Press Enter to start a new session."
	default:
		return "This terminal session has been closed. Press Enter to start a new session."
	}
}

// markTerminated flips the session's terminated bit, notifies any attached WS
// with the structured ended frame, kills the PTY, then schedules eviction after
// a grace period so a reconnecting browser still gets the ended frame (and not
// a "session not found") for a few minutes.
func (s *Store) markTerminated(sess *Session, reason string) {
	sess.mu.Lock()
	if sess.terminated {
		sess.mu.Unlock()
		return
	}
	sess.terminated = true
	sess.termReason = reason
	// Snapshot the viewers so we can notify + close them OUTSIDE the lock, then
	// drop the set.
	vs := make([]*viewer, 0, len(sess.viewers))
	for v := range sess.viewers {
		vs = append(vs, v)
	}
	sess.viewers = map[*viewer]struct{}{}
	sess.controller = nil
	if sess.cmd != nil && sess.cmd.Process != nil {
		sess.cmd.Process.Kill() //nolint:errcheck
	}
	sess.ptmx.Close()
	if sess.evictedTimer != nil {
		sess.evictedTimer.Stop()
	}
	sess.evictedTimer = time.AfterFunc(5*time.Minute, func() {
		s.mu.Lock()
		delete(s.sessions, sess.id)
		s.mu.Unlock()
	})
	sess.mu.Unlock()
	end := endedFrame(reason)
	for _, v := range vs {
		v.write(websocket.TextMessage, end) //nolint:errcheck
		v.ws.Close()
	}
}

// Terminate explicitly closes a session (UI clicked "x").
func (s *Store) Terminate(id, reason string) {
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		return
	}
	s.markTerminated(sess, reason)
}

// TerminateUser kills every session owned by userID. Called from the
// session-eviction hook so terminals die with the web session.
func (s *Store) TerminateUser(userID, reason string) {
	s.mu.Lock()
	var victims []*Session
	for _, sess := range s.sessions {
		if sess.userID == userID {
			victims = append(victims, sess)
		}
	}
	s.mu.Unlock()
	for _, v := range victims {
		s.markTerminated(v, reason)
	}
}

// ListForUser returns snapshots of all sessions belonging to userID, sorted
// oldest-first (UI tab order).
func (s *Store) ListForUser(userID string) []Snapshot {
	s.mu.Lock()
	var owned []*Session
	for _, sess := range s.sessions {
		if sess.userID == userID {
			owned = append(owned, sess)
		}
	}
	s.mu.Unlock()
	sort.Slice(owned, func(i, j int) bool { return owned[i].createdAt.Before(owned[j].createdAt) })
	out := make([]Snapshot, 0, len(owned))
	for _, sess := range owned {
		snap := sess.snapshot()
		// Don't list terminated sessions. They linger briefly (the grace period
		// lets a reconnecting window still receive the "closed" notice by id),
		// but a newly-opened terminal window must NOT resurrect them as tabs —
		// e.g. a session the user just closed with the tab's X.
		if snap.Terminated {
			continue
		}
		out = append(out, snap)
	}
	return out
}

// Get returns a session by ID, or nil.
func (s *Store) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[id]
}

// Keepalive cadence — server-initiated WebSocket pings keep dead TCP
// connections detectable. Without them, an iPad in the background for
// 10+ minutes silently has its WS killed by the OS/NAT and neither the
// browser nor the server notice until the next write fails — which is
// exactly the "frozen terminal" the user reported. With ping/pong:
//   • server pings every pingInterval
//   • browser auto-replies pong (built-in WebSocket behaviour)
//   • server's read deadline gets extended on each pong via PongHandler
//   • if pongs stop, read deadline expires → conn errors → onclose fires
//     on the browser → the client-side auto-reconnect kicks in.
const (
	pingInterval = 25 * time.Second
	readDeadline = 90 * time.Second
)

// Attach ADDS a viewer (browser window) to sess. Many viewers can be attached
// at once — they all mirror the PTY output; exactly one is the controller whose
// input reaches the PTY. The first viewer to attach becomes the controller; the
// rest are mirrors until someone takes control (Enter → take-control). Replays
// the scrollback ring to the new viewer, then blocks reading its input until the
// WS closes or the session terminates.
//
// cols/rows are the client's reported size; windowID identifies the browser
// window so the UI can show "another window is in control".
func (s *Store) Attach(sess *Session, ws *websocket.Conn, cols, rows uint16, windowID, label string) {
	v := &viewer{ws: ws, windowID: windowID, label: label, cols: cols, rows: rows}

	sess.mu.Lock()
	if sess.terminated {
		// A reconnect (or a new window) landing on an already-terminated session
		// during its grace period. Send the ended frame once, then HOLD the
		// socket open instead of closing it. Closing here is what made the
		// client's auto-reconnect fire again and re-deliver the notice forever
		// (the infinite "[…session was closed…]" loop). Holding it open means the
		// client never sees an onclose, so it never reconnects — the notice shows
		// once. We block reading until the client closes the socket itself (the
		// updated UI tears it down when the user presses Enter to start a new
		// session) or the connection drops; a read deadline bounds the wait so an
		// abandoned socket is still reclaimed.
		reason := sess.termReason
		sess.mu.Unlock()
		ws.WriteMessage(websocket.TextMessage, endedFrame(reason)) //nolint:errcheck
		ws.SetReadDeadline(time.Now().Add(6 * time.Minute))        //nolint:errcheck
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				break
			}
		}
		ws.Close()
		return
	}
	if sess.viewers == nil {
		sess.viewers = make(map[*viewer]struct{})
	}
	sess.viewers[v] = struct{}{}
	becameController := sess.controller == nil
	if becameController {
		sess.controller = v
		if cols > 0 && rows > 0 {
			sess.cols, sess.rows = cols, rows
		}
	}
	scroll := sess.scrollback.Snapshot()
	cur, cur2 := sess.cols, sess.rows
	ctlWin, ctlLabel := "", ""
	if sess.controller != nil {
		ctlWin, ctlLabel = sess.controller.windowID, sess.controller.label
	}
	sess.mu.Unlock()

	// v6.5.30 — keepalive ping/pong, now PER VIEWER. Set a read deadline; every
	// pong extends it. If the network is dead the ping write fails AND the read
	// deadline expires, ReadMessage below errors, we detach, and the client's
	// onclose auto-reconnect re-attaches (replaying scrollback).
	ws.SetReadDeadline(time.Now().Add(readDeadline))
	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(readDeadline))
		return nil
	})
	pingDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				v.writeMu.Lock()
				err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
				v.writeMu.Unlock()
				if err != nil {
					return
				}
			case <-pingDone:
				return
			}
		}
	}()
	defer close(pingDone)

	// Replay scrollback to THIS viewer only (others already have it). Strip
	// terminal report-requests so the client's emulator doesn't re-answer them
	// onto the prompt (e.g. "11;rgb:fafa/fafa/fafa").
	if len(scroll) > 0 {
		v.write(websocket.BinaryMessage, stripScrollbackQueries(scroll)) //nolint:errcheck
	}
	// Tell this viewer whether it's the controller (drives its dot colour).
	v.write(websocket.TextMessage, controlFrame(becameController, ctlWin, ctlLabel)) //nolint:errcheck
	if becameController && cur > 0 && cur2 > 0 {
		pty.Setsize(sess.ptmx, &pty.Winsize{Cols: cur, Rows: cur2}) //nolint:errcheck
	}

	// Pump WS → PTY. Only the controller's keystrokes reach the PTY; a mirror's
	// raw input is dropped (its Enter arrives as a take-control message instead).
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage {
			if c, r2, ok := parseResize(data); ok {
				v.cols, v.rows = c, r2
				sess.mu.Lock()
				isCtl := sess.controller == v
				if isCtl {
					sess.cols, sess.rows = c, r2
				}
				sess.mu.Unlock()
				if isCtl {
					pty.Setsize(sess.ptmx, &pty.Winsize{Cols: c, Rows: r2}) //nolint:errcheck
				}
				continue
			}
			switch ctrlMsgType(data) {
			case "take-control":
				sess.takeControl(v)
				continue
			case "release-control":
				sess.releaseControl(v)
				continue
			}
		}
		sess.mu.Lock()
		isCtl := sess.controller == v
		sess.mu.Unlock()
		if !isCtl {
			continue // mirror — ignore input
		}
		io.Copy(sess.ptmx, sliceReader(data)) //nolint:errcheck
		sess.mu.Lock()
		sess.lastActive = time.Now()
		sess.mu.Unlock()
	}

	// WS closed — remove this viewer (PTY keeps running; session goes
	// uncontrolled if this was the controller).
	sess.removeViewer(v)
}

// enforceUserCap evicts the oldest detached session above the cap.
func (s *Store) enforceUserCap(userID string, max int) {
	if max <= 0 {
		return
	}
	s.mu.Lock()
	var owned []*Session
	for _, sess := range s.sessions {
		if sess.userID == userID && !sess.terminated {
			owned = append(owned, sess)
		}
	}
	s.mu.Unlock()
	if len(owned) < max {
		return
	}
	// Sort by createdAt asc — oldest first.
	sort.Slice(owned, func(i, j int) bool { return owned[i].createdAt.Before(owned[j].createdAt) })
	excess := len(owned) - max + 1 // +1 to leave room for the new one
	for i := 0; i < excess; i++ {
		// Prefer detached victims; only fall through to attached if all are attached.
		victim := owned[i]
		s.markTerminated(victim, ReasonUserClose)
	}
}

func (sess *Session) snapshot() Snapshot {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	ctlWin, ctlLabel := "", ""
	if sess.controller != nil {
		ctlWin, ctlLabel = sess.controller.windowID, sess.controller.label
	}
	return Snapshot{
		ID:               sess.id,
		UserID:           sess.userID,
		Kind:             sess.kind,
		Target:           sess.target,
		Title:            sess.title,
		CreatedAt:        sess.createdAt,
		LastActive:       sess.lastActive,
		Terminated:       sess.terminated,
		TermReason:       sess.termReason,
		Attached:         len(sess.viewers) > 0,
		Cols:             sess.cols,
		Rows:             sess.rows,
		ControllerWindow: ctlWin,
		ControllerLabel:  ctlLabel,
		ViewerCount:      len(sess.viewers),
	}
}

// ID returns the session ID.
func (sess *Session) ID() string { return sess.id }

// UserID returns the owning user.
func (sess *Session) UserID() string { return sess.userID }

// ── small helpers ─────────────────────────────────────────────────────────────

type sliceReaderT struct{ b []byte; pos int }

func sliceReader(b []byte) io.Reader { return &sliceReaderT{b: b} }

func (r *sliceReaderT) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}
