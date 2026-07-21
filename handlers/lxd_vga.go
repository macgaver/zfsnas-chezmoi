package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

var lxdVGAUpgrader = websocket.Upgrader{
	CheckOrigin:  func(r *http.Request) bool { return true },
	Subprotocols: []string{"binary"},
}

func lxdSocketPath() string {
	// Incus is the only backend from 6.5.2 onward. Probe Incus's socket
	// paths (deb installs land in /var/lib/incus; some distros symlink
	// /run/incus.socket for service-style access).
	for _, p := range []string{
		"/var/lib/incus/unix.socket",
		"/run/incus/unix.socket",
		"/run/incus.socket",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func startLXDVGAOp(name string) (opID, dataSecret, ctrlSecret string, err error) {
	var stdout, stderr bytes.Buffer
	// One Incus operation backs the whole SPICE session. Every additional
	// browser-side channel (display, inputs, cursor, …) dials a new data
	// websocket to the SAME operation — that's how `incus console --type
	// vga` itself works (each accept on the local Unix socket → new WS to
	// the same opID/secret). force=true here is just to take over a stale
	// op left behind by a previous broken session; we never start more
	// than one op for a given live console.
	cmd := exec.Command("incus", "query", "-X", "POST",
		"--data", `{"type":"vga","width":1024,"height":768,"force":true}`,
		"/1.0/instances/"+name+"/console",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", "", "", fmt.Errorf("start VGA console: %s", msg)
	}
	// lxc query returns the operation object directly:
	// { "id": "<uuid>", "metadata": { "fds": { "0": "<secret>", "control": "<secret>" } } }
	var resp struct {
		ID       string `json:"id"`
		Metadata struct {
			FDs map[string]string `json:"fds"`
		} `json:"metadata"`
	}
	if err = json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return "", "", "", fmt.Errorf("parse LXD response: %w", err)
	}
	opID = resp.ID
	if opID == "" {
		return "", "", "", fmt.Errorf("unexpected LXD response (no operation ID)")
	}
	dataSecret = resp.Metadata.FDs["0"]
	if dataSecret == "" {
		return "", "", "", fmt.Errorf("no SPICE secret in LXD response; is this a VM?")
	}
	ctrlSecret = resp.Metadata.FDs["control"]
	return opID, dataSecret, ctrlSecret, nil
}

// vgaSession pools one Incus console operation across every SPICE channel
// (main + display + inputs + cursor + …) for a single VM. spice-html5 opens
// one browser→server WebSocket per channel; without pooling, each handler
// invocation would call POST /1.0/instances/<name>/console and produce a
// distinct Incus operation, each with its own SPICE TCP connection inside
// QEMU and its own connection_id. Channels after the main channel would then
// send the main channel's connection_id to a different SPICE session and
// QEMU would reply with SPICE_LINK_ERR_BAD_CONNECTION_ID (error code 8) —
// which is exactly the failure observed before this fix.
type vgaSession struct {
	opID           string
	dataSecret     string
	ctrlSecret     string
	ctrlConn       *websocket.Conn
	refCount       int
	cancelTeardown chan struct{}
}

var (
	vgaSessions   = map[string]*vgaSession{}
	vgaSessionsMu sync.Mutex
)

// vgaSessionGracePeriod gives a tiny window for spice-html5 to start opening
// the next channel after the previous one closes (page reload, WebSocket
// reset). Without it we'd tear down the op the instant the last channel
// closes, racing the next channel's dial.
const vgaSessionGracePeriod = 3 * time.Second

func makeLXDDialer(socketPath string) websocket.Dialer {
	return websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
		HandshakeTimeout: 10 * time.Second,
	}
}

// acquireVGASession returns a pooled session for `name`, starting a fresh
// Incus console operation if there isn't one already (or the cached one is
// being torn down).
func acquireVGASession(name, socketPath string) (*vgaSession, error) {
	vgaSessionsMu.Lock()
	if s, ok := vgaSessions[name]; ok {
		// Cancel any pending teardown — another channel arrived in time.
		if s.cancelTeardown != nil {
			close(s.cancelTeardown)
			s.cancelTeardown = nil
		}
		s.refCount++
		log.Printf("[vga] reuse opID=%s refs=%d", s.opID, s.refCount)
		vgaSessionsMu.Unlock()
		return s, nil
	}
	vgaSessionsMu.Unlock()

	// Fresh op outside the lock — `incus query` shells out and can take
	// 50–200 ms. Holding the global mutex that long would serialize every
	// other VM's console acquisitions.
	opID, dataSecret, ctrlSecret, err := startLXDVGAOp(name)
	if err != nil {
		return nil, err
	}
	log.Printf("[vga] new opID=%s secretLen=%d ctrlLen=%d", opID, len(dataSecret), len(ctrlSecret))

	dialer := makeLXDDialer(socketPath)
	var ctrlConn *websocket.Conn
	if ctrlSecret != "" {
		// LXD requires the control channel to be connected alongside the
		// data channel; without it LXD closes the data channel immediately.
		ctrlURL := "ws://localhost/1.0/operations/" + opID + "/websocket?secret=" + ctrlSecret
		c, _, ctrlErr := dialer.Dial(ctrlURL, nil)
		if ctrlErr != nil {
			log.Printf("[vga] dial LXD control WS error: %v", ctrlErr)
		} else {
			ctrlConn = c
			go func(cc *websocket.Conn) {
				for {
					if _, _, e := cc.ReadMessage(); e != nil {
						return
					}
				}
			}(ctrlConn)
			log.Printf("[vga] LXD control WS connected (pooled)")
		}
	}

	s := &vgaSession{
		opID:       opID,
		dataSecret: dataSecret,
		ctrlSecret: ctrlSecret,
		ctrlConn:   ctrlConn,
		refCount:   1,
	}
	vgaSessionsMu.Lock()
	if existing, ok := vgaSessions[name]; ok {
		// Another goroutine raced and inserted while we were starting.
		// Drop our op (Incus will GC it once unused) and reuse theirs.
		existing.refCount++
		vgaSessionsMu.Unlock()
		if ctrlConn != nil {
			ctrlConn.Close()
		}
		log.Printf("[vga] race: discarded opID=%s, joined existing opID=%s refs=%d", opID, existing.opID, existing.refCount)
		return existing, nil
	}
	vgaSessions[name] = s
	vgaSessionsMu.Unlock()
	return s, nil
}

func releaseVGASession(name string, s *vgaSession) {
	vgaSessionsMu.Lock()
	defer vgaSessionsMu.Unlock()
	s.refCount--
	if s.refCount > 0 {
		return
	}
	cancel := make(chan struct{})
	s.cancelTeardown = cancel
	go func() {
		select {
		case <-time.After(vgaSessionGracePeriod):
			vgaSessionsMu.Lock()
			defer vgaSessionsMu.Unlock()
			cur, ok := vgaSessions[name]
			if !ok || cur != s || s.refCount > 0 {
				return
			}
			delete(vgaSessions, name)
			if s.ctrlConn != nil {
				s.ctrlConn.Close()
			}
			log.Printf("[vga] tore down pooled session opID=%s", s.opID)
		case <-cancel:
			// A new channel grabbed the session inside the grace period.
		}
	}()
}

func invalidateVGASession(name string, s *vgaSession) {
	vgaSessionsMu.Lock()
	defer vgaSessionsMu.Unlock()
	if cur, ok := vgaSessions[name]; ok && cur == s {
		delete(vgaSessions, name)
		if s.ctrlConn != nil {
			s.ctrlConn.Close()
		}
		if s.cancelTeardown != nil {
			close(s.cancelTeardown)
			s.cancelTeardown = nil
		}
		log.Printf("[vga] invalidated pooled session opID=%s", s.opID)
	}
}

// HandleLXDVGAConsole proxies the LXD VGA SPICE channel to the browser over WebSocket.
// GET /ws/lxd-vga?name=<name>
func HandleLXDVGAConsole(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	socketPath := lxdSocketPath()
	if socketPath == "" {
		http.Error(w, "LXD Unix socket not found", http.StatusInternalServerError)
		return
	}
	log.Printf("[vga] socket=%s name=%s", socketPath, name)

	sess, err := acquireVGASession(name, socketPath)
	if err != nil {
		log.Printf("[vga] acquireVGASession error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	released := false
	releaseOnce := func() {
		if !released {
			released = true
			releaseVGASession(name, sess)
		}
	}
	defer releaseOnce()

	dialer := makeLXDDialer(socketPath)
	wsURL := "ws://localhost/1.0/operations/" + sess.opID + "/websocket?secret=" + sess.dataSecret
	lxdWS, lxdResp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.Printf("[vga] dial LXD data WS error: %v (resp=%v) — invalidating pooled session", err, lxdResp)
		// The cached operation is probably gone (Incus GC'd it). Drop the
		// cache so the next request starts a fresh op.
		invalidateVGASession(name, sess)
		releaseOnce()
		http.Error(w, "connect to LXD: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("[vga] LXD data WS connected (opID=%s)", sess.opID)
	defer lxdWS.Close()

	browserWS, err := lxdVGAUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[vga] browser upgrade error: %v", err)
		return
	}
	log.Printf("[vga] browser WS upgraded, proxying")
	defer browserWS.Close()

	// An open VGA console counts as user activity — keep the web session
	// alive so the inactivity evictor doesn't log the user out underneath a
	// console they're actively looking at.
	stopKeepalive := wsSessionKeepalive(MustSession(r).Token)
	defer stopKeepalive()

	var once sync.Once
	done := make(chan struct{})

	// SPICE-link-handshake state. We snoop the link traffic in both
	// directions only long enough to (a) snag the server's RSA pub_key
	// out of the SPICE_LINK_REPLY and (b) substitute the browser's auth
	// ticket with a Go-encrypted one. After ticket substitution every
	// subsequent frame is forwarded transparently.
	//
	// Why we re-encrypt server-side: spice-html5's hand-rolled OAEP
	// (and even Web Crypto in some browsers) produces ciphertext that
	// modern QEMU/Spice (Incus 6.0 on Debian 13) won't accept against
	// the empty-string password set by `disable-ticketing=on`. A Go
	// test with crypto/rsa.EncryptOAEP(sha1, …, []byte{}, nil) is
	// accepted every time, so we just do the encryption here.
	var (
		rsaPub        *rsa.PublicKey
		ticketRewrote bool
		stateMu       sync.Mutex
	)
	captureLinkReply := func(msg []byte) {
		// SPICE_LINK_HEADER (16) + SPICE_LINK_REPLY (≥ 4 + 162 …)
		if len(msg) < 16+4+spiceTicketPubkeyBytes {
			return
		}
		errCode := binary.LittleEndian.Uint32(msg[16:20])
		if errCode != 0 {
			return
		}
		pubDER := msg[20 : 20+spiceTicketPubkeyBytes]
		pub, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil {
			log.Printf("[vga] parse SPKI from LINK_REPLY: %v", err)
			return
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			log.Printf("[vga] LINK_REPLY pub_key is not RSA")
			return
		}
		stateMu.Lock()
		rsaPub = rp
		ticketRewrote = false
		stateMu.Unlock()
		log.Printf("[vga] captured RSA pubkey (modulus %d bits)", rp.N.BitLen())
	}
	rewriteTicket := func(msg []byte) ([]byte, bool) {
		stateMu.Lock()
		defer stateMu.Unlock()
		if len(msg) != 4+spiceTicketKeyPairBytes {
			return msg, false
		}
		if rsaPub == nil {
			log.Printf("[vga] ticket-shaped frame (%d bytes) but no RSA pubkey captured yet — passing through", len(msg))
			return msg, false
		}
		if ticketRewrote {
			log.Printf("[vga] ticket-shaped frame after first rewrite — passing through")
			return msg, false
		}
		// Empty plaintext: matches the empty SPICE password Incus configures
		// via disable-ticketing=on. memcmp(decrypted, "", 0) always passes.
		enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rsaPub, []byte{}, nil)
		if err != nil {
			log.Printf("[vga] rsa.EncryptOAEP: %v", err)
			return msg, false
		}
		ticket := make([]byte, 4+spiceTicketKeyPairBytes)
		binary.LittleEndian.PutUint32(ticket[0:4], spiceCommonCapAuthSpice)
		copy(ticket[4:], enc)
		ticketRewrote = true
		log.Printf("[vga] re-encrypted auth ticket server-side (browser ticket discarded)")
		return ticket, true
	}

	// LXD → browser
	go func() {
		defer once.Do(func() { close(done) })
		for {
			mt, msg, err := lxdWS.ReadMessage()
			if err != nil {
				log.Printf("[vga] lxd→browser read err: %v", err)
				return
			}
			// Drop stray empty TEXT frames coming from Incus's WS proxy.
			// Incus's `incus query --console` websocket bridge sends an
			// empty WebSocket text frame (opcode=1, length=0) between
			// SPICE binary messages — verified with a direct unix-socket
			// test that authenticates fine, gets SPICE_MSG_MAIN_INIT, then
			// receives this empty frame. spice-html5 negotiates the
			// "binary" subprotocol and chokes on text frames; the browser
			// closes the connection right after with "Unexpected close
			// while ready", which is exactly the user-facing error we saw.
			// Filtering these frames out makes the proxy fully transparent
			// from the SPICE client's point of view.
			if mt == websocket.TextMessage && len(msg) == 0 {
				continue
			}
			log.Printf("[vga] lxd→browser: type=%d len=%d", mt, len(msg))
			if len(msg) == 4 {
				log.Printf("[vga] lxd→browser 4-byte auth reply: % x (decoded=%d)", msg, binary.LittleEndian.Uint32(msg))
			}
			// 202 bytes is the SPICE_LINK_REPLY frame (16-byte header +
			// 186-byte body for the standard caps shape). Snag the pub_key.
			if len(msg) == 202 {
				captureLinkReply(msg)
			}
			if err := browserWS.WriteMessage(mt, msg); err != nil {
				log.Printf("[vga] lxd→browser write err: %v", err)
				return
			}
		}
	}()
	// browser → LXD
	go func() {
		defer once.Do(func() { close(done) })
		for {
			mt, msg, err := browserWS.ReadMessage()
			if err != nil {
				log.Printf("[vga] browser→lxd read err: %v", err)
				return
			}
			log.Printf("[vga] browser→lxd: type=%d len=%d", mt, len(msg))
			// 132-byte frame is the SPICE_LINK_AUTH_TICKET (4-byte
			// auth_mechanism + 128-byte encrypted_data). Substitute it.
			if rewritten, ok := rewriteTicket(msg); ok {
				msg = rewritten
			}
			if err := lxdWS.WriteMessage(mt, msg); err != nil {
				log.Printf("[vga] browser→lxd write err: %v", err)
				return
			}
		}
	}()

	<-done
	log.Printf("[vga] proxy done for %s", name)
}

// spiceTicketPubkeyBytes / spiceTicketKeyPairBytes / spiceCommonCapAuthSpice
// are the SPICE protocol constants. Defined locally because we don't pull in
// a SPICE library — the values are stable across SPICE versions.
const (
	spiceTicketPubkeyBytes  = 162
	spiceTicketKeyPairBytes = 128
	spiceCommonCapAuthSpice = 1
)

// ServeLXDVGAPage serves the VGA console viewer using spice-html5.
// GET /lxd-vga-console/{name}
func ServeLXDVGAPage(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	if name == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// embed=1 renders the page for use inside a multi-terminal tab (toolbar
	// pinned to the bottom, the close button closes the tab instead of the window).
	// server_id, when set, makes every API + SPICE call route through the
	// per-peer relay so a peer VM's console works from the home portal.
	embed := r.URL.Query().Get("embed") == "1"
	serverID := r.URL.Query().Get("server_id")
	// SecurityHeaders middleware sets X-Frame-Options: DENY on every response.
	// In embed mode this page is rendered inside the same-origin multi-terminal
	// iframe, so DENY would leave the tab blank — relax to SAMEORIGIN (still
	// blocks cross-origin framing). Mirrors the file-browser preview override.
	if embed {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	fmt.Fprintf(w, lxdVGAPageHTML, name, name, name, serverID, embed)
}

const lxdVGAPageHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>VGA Console — %s</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
html, body { width:100%%; height:100%%; background:#000; overflow:hidden; display:flex; flex-direction:column; font-family:system-ui,sans-serif; }
#toolbar { background:#1a1a1a; border-bottom:1px solid #2a2a2a; padding:6px 14px; display:flex; align-items:center; gap:10px; flex-shrink:0; font-size:13px; color:#bbb; }
#toolbar strong { color:#fff; }
#toolbar button { background:#2a2a2a; color:#ccc; border:1px solid #444; border-radius:4px; padding:3px 10px; cursor:pointer; font-size:12px; }
#toolbar button:hover { background:#3a3a3a; color:#fff; }
#status { margin-left:auto; font-size:12px; color:#666; }
/* Close-window button — sits to the right of the SPICE connection status
   (which itself is pushed to the far right by margin-left:auto) so it lands
   in the canonical "X to close" corner. window.close() works because the
   VGA viewer is always opened via window.open() in the parent ZNAS UI;
   browsers allow JS-opened windows to close themselves even with the
   noopener flag the parent uses. Square shape + red-on-hover signals a
   destructive action without putting it in the regular toolbar flow. */
#close-btn { padding:3px 8px; font-size:13px; line-height:1; min-width:24px; }
#close-btn:hover { background:#bf3a3a; color:#fff; border-color:#7a2a2a; }
#kbd-wrap { position:relative; display:inline-block; }
#kbd-menu { display:none; position:absolute; top:calc(100%% + 4px); left:0; background:#2a2a2a; border:1px solid #444; border-radius:4px; min-width:170px; z-index:100; box-shadow:0 4px 12px rgba(0,0,0,.6); }
.kbd-item { padding:7px 14px; cursor:pointer; font-size:12px; color:#ccc; white-space:nowrap; }
.kbd-item:hover { background:#3a3a3a; color:#fff; }
/* Function-key grid in the keyboard menu — for users whose physical keyboard
   has no F-row (some laptops, ChromeOS devices, on-screen keyboards). Sending
   F12 here is the manual workaround when OVMF auto-boot fails to find the
   CDROM and the user wants the boot picker. */
#fk-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:4px; padding:6px 8px; }
.fk-btn { background:#1f1f24; border:1px solid #3a3a3a; color:#ccc; border-radius:3px; padding:5px 0; font-size:11px; cursor:pointer; text-align:center; }
.fk-btn:hover { background:#3a3a3a; color:#fff; }
/* Power dropdown — button label tracks live VM status and color-codes it
   the same way the rest of the app does (Running=green, Stopped=grey,
   Frozen/transient=amber, Error=red). Shares the dropdown stylesheet
   with kbd-menu / cur-menu so it stays visually consistent. */
#pwr-wrap { position:relative; display:inline-block; }
#pwr-btn { font-weight:600; min-width:84px; }
#pwr-menu { display:none; position:absolute; top:calc(100%% + 4px); left:0; background:#2a2a2a; border:1px solid #444; border-radius:4px; min-width:200px; z-index:100; box-shadow:0 4px 12px rgba(0,0,0,.6); }
#status.ok   { color:#4ade80; }
#status.err  { color:#f87171; }
#status.warn { color:#fbbf24; }
/* spice-html5 forcibly sets style.height = <guest framebuffer height>px
   on #spice-area whenever the primary surface arrives (see vendor file
   ~5811). On guests rendering at 1024x768 / 1280x1024 etc., that inline
   height frequently exceeds the body's flex share, so the bottom rows of
   the canvas fall outside the viewport — the "missing pixels at the
   bottom" symptom. !important here beats the inline style and the flex
   item keeps its 1fr share. min-height:0 is the standard flexbox dodge
   that allows a column-flex item to shrink below its content size.

   v6.5.30: the canvas box is sized to EXACTLY match the container
   (width:100%%/height:100%% on the canvas) and object-fit:contain handles
   aspect preservation INSIDE the box. The previous max-*+width:auto
   approach allowed the canvas to keep its intrinsic height when
   align-items:center was on the parent — leaving a few rows clipped at
   the bottom. Sizing the box to the container removes the possibility of
   overflow entirely; any aspect mismatch produces letterbox instead of
   clip. Pointer coords are re-mapped to framebuffer pixels by the
   _znasMouseFB helper in spice-html5.js, which is aware of the letterbox
   so clicks in the letterbox area still resolve to the nearest valid
   framebuffer pixel rather than out-of-bounds coords. */
#spice-area { flex:1 1 0 !important; min-height:0 !important; height:auto !important; overflow:hidden; position:relative; display:flex; align-items:stretch; justify-content:stretch; }
#spice-area canvas { display:block; width:100%%; height:100%%; object-fit:contain; }
#notice { position:absolute; color:#666; font-size:13px; text-align:center; line-height:1.7; pointer-events:none; }
/* Pointer-style overrides applied to the SPICE canvas. spice-html5 sets an
   inline cursor style on every frame (often "none" when the guest doesn't
   send cursor data — which is why the pointer can vanish entirely on VMs
   without a SPICE agent or qxl driver). !important is required to keep our
   choice visible. The guest OS may also draw its own cursor; these styles
   only affect the host-side pointer the browser renders over the canvas. */
#spice-area.cur-default canvas    { cursor: default !important; }
#spice-area.cur-crosshair canvas  { cursor: crosshair !important; }
#spice-area.cur-cell canvas       { cursor: cell !important; }
#spice-area.cur-hidden canvas     { cursor: none !important; }
/* "Large arrow" — 32x32 SVG embedded inline so it scales up the host pointer
   for high-DPI / TV displays without a separate asset. */
#spice-area.cur-large canvas {
  cursor: url("data:image/svg+xml;utf8,%%3Csvg xmlns='http://www.w3.org/2000/svg' width='32' height='32' viewBox='0 0 32 32'%%3E%%3Cpath d='M4 2 L4 26 L11 19 L15 28 L19 26 L15 18 L24 18 Z' fill='%%23fff' stroke='%%23000' stroke-width='1.5' stroke-linejoin='round'/%%3E%%3C/svg%%3E") 4 2, default !important;
}
/* "Dot" — a 14x14 ring with a black core, drawn at the hot-spot. Helpful for
   pixel-precise positioning when the guest cursor is a thin line and gets
   lost against the desktop. */
#spice-area.cur-dot canvas {
  cursor: url("data:image/svg+xml;utf8,%%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 14 14'%%3E%%3Ccircle cx='7' cy='7' r='5.5' fill='none' stroke='%%23fff' stroke-width='2'/%%3E%%3Ccircle cx='7' cy='7' r='1.5' fill='%%23000'/%%3E%%3C/svg%%3E") 7 7, crosshair !important;
}
#cdrom-menu .kbd-item.current { background:#1a3a1a; color:#9be39b; }
#cdrom-menu .kbd-item.eject   { color:#fbbf24; }
#cdrom-menu .kbd-item.muted   { color:#666; cursor:default; }
#cdrom-menu .kbd-item.muted:hover { background:#2a2a2a; color:#666; }
#cdrom-menu .kbd-sub { padding:6px 14px; font-size:11px; color:#8a8a8a; border-top:1px solid #3a3a3a; }
#cdrom-btn.has-disc { color:#9be39b; }
/* Embedded-in-a-tab mode: the button bar lives at the BOTTOM of the pane,
   so flip the body's column flow and move the toolbar's border + all of its
   dropdown menus to open upward (!important beats the inline top: on the
   cdrom/cursor menus). */
body[data-embed] { flex-direction:column-reverse; }
body[data-embed] #toolbar { border-bottom:none; border-top:1px solid #2a2a2a; }
body[data-embed] #kbd-menu,
body[data-embed] #pwr-menu,
body[data-embed] #cdrom-menu,
body[data-embed] #cur-menu { top:auto !important; bottom:calc(100%% + 4px) !important; }
</style>
</head>
<body>
<div id="toolbar">
  <span>VGA Console — <strong>%s</strong></span>
  <button onclick="reconnect()">Reconnect</button>
  <div id="pwr-wrap">
    <button id="pwr-btn" onclick="togglePwrMenu(event)" title="VM power state">…</button>
    <div id="pwr-menu">
      <div class="kbd-item" data-pwr-action="start"   onclick="pwrAction('start')"><svg class="znas-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><polygon points="6 3 20 12 6 21 6 3"/></svg> Start</div>
      <div class="kbd-item" data-pwr-action="restart" onclick="pwrAction('restart')">⟳ Restart (graceful)</div>
      <div class="kbd-item" data-pwr-action="reset"   onclick="pwrAction('reset')" style="color:#ff8a8a;"><svg class="znas-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z"/></svg> Hard Reboot</div>
      <div class="kbd-item" data-pwr-action="stop"    onclick="pwrAction('stop')" style="color:#fbbf24;"><svg class="znas-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><rect width="18" height="18" x="3" y="3" rx="2"/></svg> Stop</div>
    </div>
  </div>
  <div id="kbd-wrap">
    <button onclick="toggleKbdMenu(event)" title="Send keyboard shortcut"><svg class="znas-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><path d="M10 8h.01"/><path d="M12 12h.01"/><path d="M14 8h.01"/><path d="M16 12h.01"/><path d="M18 8h.01"/><path d="M6 8h.01"/><path d="M7 16h10"/><path d="M8 12h.01"/><rect width="20" height="16" x="2" y="4" rx="2"/></svg></button>
    <div id="kbd-menu">
      <div class="kbd-item" onclick="kbdCtrlAltDel()">Ctrl+Alt+Delete</div>
      <div class="kbd-sub" style="border-top:1px solid #3a3a3a;margin-top:4px;padding-top:6px;">Function keys</div>
      <div id="fk-grid">
        <div class="fk-btn" onclick="sendVGAKey(0x3B)">F1</div>
        <div class="fk-btn" onclick="sendVGAKey(0x3C)">F2</div>
        <div class="fk-btn" onclick="sendVGAKey(0x3D)">F3</div>
        <div class="fk-btn" onclick="sendVGAKey(0x3E)">F4</div>
        <div class="fk-btn" onclick="sendVGAKey(0x3F)">F5</div>
        <div class="fk-btn" onclick="sendVGAKey(0x40)">F6</div>
        <div class="fk-btn" onclick="sendVGAKey(0x41)">F7</div>
        <div class="fk-btn" onclick="sendVGAKey(0x42)">F8</div>
        <div class="fk-btn" onclick="sendVGAKey(0x43)">F9</div>
        <div class="fk-btn" onclick="sendVGAKey(0x44)">F10</div>
        <div class="fk-btn" onclick="sendVGAKey(0x57)">F11</div>
        <div class="fk-btn" onclick="sendVGAKey(0x58)">F12</div>
      </div>
    </div>
  </div>
  <div id="cdrom-wrap" style="position:relative;display:none;">
    <button id="cdrom-btn" onclick="toggleCDROMMenu(event)" title="CD/DVD drive"><svg class="znas-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="2"/></svg></button>
    <div id="cdrom-menu" style="display:none;position:absolute;top:calc(100%% + 4px);left:0;background:#2a2a2a;border:1px solid #444;border-radius:4px;min-width:240px;max-width:340px;max-height:60vh;overflow-y:auto;z-index:100;box-shadow:0 4px 12px rgba(0,0,0,.6);"></div>
  </div>
  <div id="cur-wrap" style="position:relative;display:inline-block;">
    <button onclick="toggleCursorMenu(event)" title="Pointer style"><svg class="znas-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><rect x="5" y="2" width="14" height="20" rx="7"/><path d="M12 6v4"/></svg></button>
    <div id="cur-menu" style="display:none;position:absolute;top:calc(100%% + 4px);left:0;background:#2a2a2a;border:1px solid #444;border-radius:4px;min-width:170px;z-index:100;box-shadow:0 4px 12px rgba(0,0,0,.6);">
      <div class="kbd-item" data-cur="default"   onclick="setCursor('default')">Default arrow</div>
      <div class="kbd-item" data-cur="large"     onclick="setCursor('large')">Large arrow</div>
      <div class="kbd-item" data-cur="crosshair" onclick="setCursor('crosshair')">Crosshair</div>
      <div class="kbd-item" data-cur="dot"       onclick="setCursor('dot')">Precision dot</div>
      <div class="kbd-item" data-cur="cell"      onclick="setCursor('cell')">Cell (cell-grid)</div>
      <div class="kbd-item" data-cur="hidden"    onclick="setCursor('hidden')">Hidden (guest only)</div>
    </div>
  </div>
  <button onclick="document.getElementById('spice-area').requestFullscreen()">Fullscreen</button>
  <span id="status">Connecting…</span>
  <button id="close-btn" onclick="closeConsole()" title="Close console"><svg class="znas-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="vertical-align:-0.14em"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button>
</div>
<div id="spice-area">
  <span id="notice">Connecting to VGA console…</span>
</div>
<script src="/static/vendor/spice-html5.js?v=6.5.30-letterbox"></script>
<script>` + znasIconsJS + `
const name = %q;
const serverId = %q;
const embedded = %t;
const proto = location.protocol === 'https:' ? 'wss' : 'ws';
// When this console targets a peer VM (serverId set), route every API + WS
// call through the generic per-peer relay so they reach the peer instead of
// this home server. Local consoles return the path unchanged.
function apiURL(p) { return serverId ? ('/interlink-relay/' + encodeURIComponent(serverId) + p) : p; }
function wsURL(p)  { return apiURL(p); }
// The close button in embed mode can't close an iframe — ask the parent tab to close us.
function closeConsole() {
  if (embedded) {
    try { window.parent.postMessage({ type:'znas-vga-close', name: name }, location.origin); } catch(e) {}
  } else {
    window.close();
  }
}
let sc;
// Connection state machine drives the top-right badge and the auto-reconnect
// loop. Values: 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'vm-offline'
let _state = 'idle';
let _reconnectTimer = null;
let _userInitiatedReconnect = false;

function setStatus(msg, cls) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = cls || '';
}
function setNotice(msg) {
  let el = document.getElementById('notice');
  if (!el) {
    el = document.createElement('span');
    el.id = 'notice';
    document.getElementById('spice-area').appendChild(el);
  }
  el.textContent = msg;
}
function clearNotice() {
  const n = document.getElementById('notice');
  if (n) n.remove();
}

function _setState(s) { _state = s; }

function _cancelReconnect() {
  if (_reconnectTimer) { clearTimeout(_reconnectTimer); _reconnectTimer = null; }
}

// Reset the SPICE area back to a single notice — wipes any stale canvas left
// over from the previous connection so the user doesn't see a frozen frame
// behind the "Reconnecting…" status.
function _resetSpiceArea(noticeText) {
  const area = document.getElementById('spice-area');
  area.innerHTML = '<span id="notice">' + (noticeText || 'Connecting…') + '</span>';
}

function reconnect() {
  _userInitiatedReconnect = true;
  _cancelReconnect();
  if (sc) { try { sc.stop(); } catch(e) {} sc = null; }
  _resetSpiceArea('Connecting to VGA console…');
  _setState('connecting');
  setStatus('Connecting…');
  setTimeout(connect, 200);
}

// Poll the VM's run state and decide what to do next:
//   - Running          → start a fresh SPICE connection.
//   - Stopped/Frozen/… → surface that in the badge and keep polling.
//   - Probe failed     → keep polling (treat as transient network blip).
async function _probeAndReconnect() {
  _reconnectTimer = null;
  let vmStatus = '';
  let probeFailed = false;
  try {
    const r = await fetch(apiURL('/api/incus/instances/' + encodeURIComponent(name) + '/status'), { cache: 'no-store' });
    if (r.ok) {
      const d = await r.json();
      vmStatus = (d && d.status) || '';
    } else {
      probeFailed = true;
    }
  } catch(_) { probeFailed = true; }

  if (vmStatus === 'Running') {
    _setState('connecting');
    setStatus('Reconnecting…', 'warn');
    setNotice('VM is running — reattaching SPICE…');
    if (sc) { try { sc.stop(); } catch(e) {} sc = null; }
    connect();
    return;
  }

  if (vmStatus) {
    _setState('vm-offline');
    setStatus('VM ' + vmStatus, 'err');
    setNotice('Waiting for VM to start (' + vmStatus + ')…');
  } else if (probeFailed) {
    _setState('reconnecting');
    setStatus('Reconnecting…', 'warn');
    setNotice('Status probe failed — retrying…');
  }
  _reconnectTimer = setTimeout(_probeAndReconnect, 3000);
}

// Clear the stale canvas/audio nodes spice-html5 leaves behind, then schedule
// the first probe. Quick first retry so a clean reboot reattaches in ~1s
// once the VM's SPICE socket is back up.
function _scheduleReconnect(firstDelayMs) {
  _cancelReconnect();
  const area = document.getElementById('spice-area');
  if (area) {
    area.querySelectorAll('canvas, audio, video').forEach(n => n.remove());
  }
  _reconnectTimer = setTimeout(_probeAndReconnect, firstDelayMs == null ? 1200 : firstDelayMs);
}

function connect() {
  _userInitiatedReconnect = false;
  const wsUrl = proto + '://' + location.host + wsURL('/ws/lxd-vga?name=' + encodeURIComponent(name));
  try {
    sc = new SpiceMainConn({
      uri: wsUrl,
      screen_id: 'spice-area',
      onerror: function(e) {
        // spice-html5 calls onerror for every disconnect, including normal
        // ones (VM rebooted / shut down): the WS-close handler synthesises an
        // "Unexpected close" Error. We treat all of them the same: clear the
        // stale frame, surface a transient status, then probe + auto-reconnect.
        const wasConnected = _state === 'connected';
        _setState('reconnecting');
        setStatus(wasConnected ? 'Reconnecting…' : 'Disconnected', 'warn');
        setNotice((wasConnected ? 'Connection lost' : ('Connection error: ' + (e && e.message || 'disconnected'))) + ' — checking VM status…');
        _scheduleReconnect();
      },
      onagent: function() {
        _setState('connected');
        setStatus('Connected', 'ok');
        clearNotice();
      }
    });
    // Detect connect-success even for VMs without a SPICE agent (where
    // onagent never fires) by watching for spice-html5 injecting its canvas.
    const area = document.getElementById('spice-area');
    const obs = new MutationObserver(() => {
      const cv = area.querySelector('canvas');
      if (cv) {
        _setState('connected');
        setStatus('Connected', 'ok');
        clearNotice();
        bindCanvasFocus(cv);
        obs.disconnect();
      }
    });
    obs.observe(area, { childList: true, subtree: true });
  } catch(e) {
    setStatus('Failed: ' + e.message, 'err');
    setNotice('Could not start SPICE client: ' + e.message + ' — retrying…');
    _setState('reconnecting');
    _scheduleReconnect(2000);
  }
}

// iPad/iOS Safari drops keyboard input as soon as the canvas loses focus
// (which happens whenever a toolbar button is tapped, the on-screen keyboard
// is dismissed, or the page sits idle for a few seconds with no pointer
// activity). spice-html5 attaches keydown/keyup listeners directly to the
// canvas (see vendor/spice-html5.js lines 6077–6082), so an unfocused canvas
// silently swallows every keystroke — that's why moving the mouse/finger
// "fixes" it temporarily. We aggressively keep focus on the canvas.
function bindCanvasFocus(canvas) {
  if (!canvas) return;
  canvas.setAttribute('tabindex', '0');
  canvas.style.outline = 'none';
  try { canvas.focus({ preventScroll: true }); } catch(_) { canvas.focus(); }

  // Re-focus immediately after blur. setTimeout(0) lets the next focus target
  // settle so we don't fight a deliberate focus on a toolbar button while its
  // onclick handler is running.
  canvas.addEventListener('blur', function() {
    setTimeout(function() {
      if (document.visibilityState === 'visible' && document.body.contains(canvas)) {
        try { canvas.focus({ preventScroll: true }); } catch(_){}
      }
    }, 0);
  });

  // Tap inside the console area → focus the canvas. Covers iPad finger taps
  // and mouse clicks with one handler.
  var area = document.getElementById('spice-area');
  if (area) {
    area.addEventListener('pointerdown', function() {
      try { canvas.focus({ preventScroll: true }); } catch(_){}
    });
  }

  // Safety net: if focus drifts to <body> (default landing spot after the
  // iPad on-screen keyboard dismiss or app-switch return), pull it back.
  // Skipped while the page is hidden so we don't yank focus from another tab.
  setInterval(function() {
    if (document.visibilityState !== 'visible') return;
    var ae = document.activeElement;
    if (ae !== canvas && (ae === document.body || ae === null || ae === document.documentElement)) {
      try { canvas.focus({ preventScroll: true }); } catch(_){}
    }
  }, 750);
}

function _closeAllToolbarMenus() {
  ['kbd-menu','cur-menu','cdrom-menu','pwr-menu'].forEach(function(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}
function toggleKbdMenu(e) {
  e.stopPropagation();
  const m = document.getElementById('kbd-menu');
  const open = m.style.display !== 'block';
  _closeAllToolbarMenus();
  if (open) m.style.display = 'block';
}
function togglePwrMenu(e) {
  e.stopPropagation();
  const m = document.getElementById('pwr-menu');
  const open = m.style.display !== 'block';
  _closeAllToolbarMenus();
  if (open) m.style.display = 'block';
}

// sendVGAKey emits a single key-down/key-up pair through the SPICE input
// channel. Used by the F1-F12 buttons in the keyboard menu so users on
// laptops without a physical F-row can still send those scancodes — the
// most common use is pressing F12 to reach OVMF's boot picker when an
// installer ISO needs to be selected manually.
//
// Scancodes are PS/2 set 1 (the same encoding spice-html5 uses everywhere
// else for key.code). F1-F10 are 0x3B-0x44 contiguous; F11/F12 jump to
// 0x57/0x58 because IBM ran out of room in the original AT keyboard's
// scancode block.
function sendVGAKey(scancode) {
  if (!sc || !sc.inputs || sc.inputs.state !== 'ready') return;
  const msg = new SpiceMiniData();
  const down = new SpiceMsgcKeyDown();
  down.code = scancode;
  msg.build_msg(SPICE_MSGC_INPUTS_KEY_DOWN, down);
  sc.inputs.send_msg(msg);
  const up = new SpiceMsgcKeyUp();
  up.code = scancode;
  msg.build_msg(SPICE_MSGC_INPUTS_KEY_UP, up);
  sc.inputs.send_msg(msg);
}
// Ctrl+C from the VGA console: stop the BROWSER from stealing it for "copy",
// then let spice-html5's own canvas keydown handler forward it to the guest
// with its normal modifier tracking — the same path every other key uses.
//
// We do NOT inject a synthetic scancode sequence and do NOT stopPropagation:
// an earlier version did, and its synthetic Ctrl-down/up collided with the
// physical Ctrl that spice already tracks, leaving Ctrl STUCK DOWN on the guest
// after the first use (so nothing interrupted until a reconnect reset the
// keyboard state). Capture phase runs before the browser's copy and before the
// canvas listener; preventDefault cancels the copy; the event still propagates
// to spice's handler, which sends a correctly-paired Ctrl+C.
document.addEventListener('keydown', function(ev) {
  if (ev.ctrlKey && !ev.shiftKey && !ev.altKey && !ev.metaKey
      && (ev.key === 'c' || ev.key === 'C')) {
    ev.preventDefault();
  }
}, true);

function toggleCursorMenu(e) {
  e.stopPropagation();
  const m = document.getElementById('cur-menu');
  const open = m.style.display !== 'block';
  _closeAllToolbarMenus();
  if (open) m.style.display = 'block';
}
document.addEventListener('click', _closeAllToolbarMenus);

// --- CD/DVD drive picker ----------------------------------------------------
// Visible only when the VM has at least one CDROM drive configured. Clicking
// it opens a list of ISOs available in the same storage pool plus an Eject
// option. The change writes raw.qemu, which QEMU only re-reads at start, so
// running VMs need a restart for the new disc to appear.
let _cdromState = { configured: [], available: [], pool: '', running: false };

async function refreshCDROMState() {
  try {
    const r = await fetch(apiURL('/api/incus/instances/' + encodeURIComponent(name) + '/cdroms'), { cache:'no-store' });
    if (!r.ok) { document.getElementById('cdrom-wrap').style.display = 'none'; return; }
    _cdromState = await r.json();
  } catch(_) { document.getElementById('cdrom-wrap').style.display = 'none'; return; }
  const wrap = document.getElementById('cdrom-wrap');
  const btn  = document.getElementById('cdrom-btn');
  // Show the disc button for every VM. Containers don't have a CDROM concept
  // in this UI; everything else benefits from being able to mount/swap an ISO
  // mid-session (Windows driver install, ISO-based recovery, etc.) even when
  // no disc is currently inserted.
  if (!_cdromState.is_vm) {
    wrap.style.display = 'none';
    return;
  }
  wrap.style.display = 'inline-block';
  const cur = (_cdromState.configured && _cdromState.configured[0]) || null;
  if (cur && cur.filename) {
    btn.classList.add('has-disc');
    btn.title = 'CD/DVD: ' + cur.filename;
  } else {
    btn.classList.remove('has-disc');
    btn.title = 'CD/DVD drive (empty)';
  }
}

function _renderCDROMMenu() {
  const m = document.getElementById('cdrom-menu');
  const cur = (_cdromState.configured && _cdromState.configured[0]) || { filename: '' };
  // Build with DOM nodes rather than HTML string concatenation so ISO names
  // containing quotes / backslashes / HTML metacharacters are always handled
  // correctly. .textContent escapes for display; data-iso carries the raw
  // value to the click handler.
  m.innerHTML = '';
  const eject = document.createElement('div');
  eject.className = 'kbd-item eject' + (cur.filename ? '' : ' muted');
  icoLabel(eject, ico('eject', {size:13}) + ' Empty (eject)');
  eject.dataset.iso = '';
  eject.addEventListener('click', function() { swapCDROM(''); });
  m.appendChild(eject);
  if (!_cdromState.available || !_cdromState.available.length) {
    const empty = document.createElement('div');
    empty.className = 'kbd-item muted';
    empty.textContent = 'No ISOs on any pool';
    m.appendChild(empty);
  } else {
    // Group ISOs by pool so the operator can tell where each disc lives.
    // The VM's root pool floats to the top — that's the "default" pool
    // the picker used to show alone, and is the most common pick.
    const byPool = {};
    const order = [];
    _cdromState.available.forEach(function(iso) {
      const p = iso.pool || _cdromState.pool || '?';
      if (!byPool[p]) { byPool[p] = []; order.push(p); }
      byPool[p].push(iso);
    });
    const rootPool = _cdromState.pool || '';
    order.sort(function(a, b) {
      if (a === rootPool) return -1;
      if (b === rootPool) return 1;
      return a.localeCompare(b);
    });
    order.forEach(function(p) {
      const hdr = document.createElement('div');
      hdr.className = 'kbd-sub';
      hdr.textContent = 'Pool: ' + p;
      m.appendChild(hdr);
      byPool[p].forEach(function(iso) {
        // "current" is filename-only — Incus paths embed the pool name,
        // but two different pools could legitimately hold same-named ISOs;
        // mark current only when both the filename and pool match what's
        // attached. The configured path includes the pool's mount point so
        // a substring check on the pool name is enough.
        const isCur = iso.name === cur.filename &&
          (_cdromState.configured && _cdromState.configured[0] &&
           _cdromState.configured[0].path &&
           _cdromState.configured[0].path.indexOf('/' + p + '/') !== -1);
        const row = document.createElement('div');
        row.className = 'kbd-item' + (isCur ? ' current' : '');
        icoLabel(row, (isCur ? ico('circle-fill', {size:11}) + ' ' : '') + iso.name);
        row.dataset.iso = iso.name;
        row.dataset.pool = p;
        row.addEventListener('click', function() { swapCDROM(iso.name, p); });
        m.appendChild(row);
      });
    });
  }
  if (_cdromState.running) {
    const hint = document.createElement('div');
    hint.className = 'kbd-sub';
    hint.textContent = 'Restart the VM to apply a new disc.';
    m.appendChild(hint);
  }
}

function toggleCDROMMenu(e) {
  e.stopPropagation();
  const m = document.getElementById('cdrom-menu');
  const open = m.style.display !== 'block';
  _closeAllToolbarMenus();
  if (open) {
    refreshCDROMState().then(function() {
      _renderCDROMMenu();
      m.style.display = 'block';
    });
  }
}

async function swapCDROM(filename, pool) {
  document.getElementById('cdrom-menu').style.display = 'none';
  try {
    const r = await fetch(apiURL('/api/incus/instances/' + encodeURIComponent(name) + '/cdroms/swap'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: filename, pool: pool || '' })
    });
    const d = await r.json().catch(function(){ return {}; });
    if (!r.ok || d.ok === false) {
      setStatus('Disc swap failed', 'err');
      setNotice('Disc swap failed: ' + (d.error || r.statusText));
      setTimeout(clearNotice, 4000);
      return;
    }
    await refreshCDROMState();
    if (d.running) {
      setStatus('Restart VM to apply', 'warn');
    } else {
      setStatus(filename ? ('Loaded ' + filename) : 'Drive emptied', 'ok');
    }
  } catch(e) {
    setStatus('Disc swap error', 'err');
    setNotice('Disc swap error: ' + (e && e.message || e));
  }
}
function kbdCtrlAltDel() {
  document.getElementById('kbd-menu').style.display = 'none';
  sendCtrlAltDel(sc);
}

// pwrAction routes the four power-button entries to their respective Incus
// endpoints. start / stop / restart are the standard graceful lifecycle
// actions; reset is the "physical reset button" hard reboot used when
// Ctrl+Alt+Del or a graceful restart can't unstick a frozen OS, BSOD, or
// hung OVMF setup. Each destructive action confirms in-DOM (project policy:
// no native confirm() popups). After any action that resets the CPU
// (start/restart/reset/stop) the SPICE channel is reconnected so the user
// doesn't sit on a stale frame.
function pwrAction(action) {
  document.getElementById('pwr-menu').style.display = 'none';
  const meta = {
    start:   { label: 'Start',        verbing: 'Starting',   danger: false, body: 'Power on <strong>' + name + '</strong>?' },
    stop:    { label: 'Stop',         verbing: 'Stopping',   danger: true,  body: 'Stop <strong>' + name + '</strong>? Sends ACPI shutdown; if the guest does not respond Incus forces it off after a timeout.' },
    restart: { label: 'Restart',      verbing: 'Restarting', danger: true,  body: 'Restart <strong>' + name + '</strong>? The guest receives ACPI shutdown then is started again.' },
    reset:   { label: 'Hard Reboot',  verbing: 'Resetting',  danger: true,  body: 'Hard reboot <strong>' + name + '</strong>? This power-cycles the VM immediately — unsaved guest state is lost (same effect as the physical Reset button). Use when Ctrl+Alt+Del or a graceful restart can\'t unstick a frozen OS.' },
  }[action];
  if (!meta) return;
  // Start is non-destructive — skip the confirm dialog so users don't have
  // to click twice on the common case of "VM stopped, hit Start".
  const run = async () => {
    setStatus(meta.verbing + '…', 'warn');
    try {
      const r = await fetch(apiURL('/api/incus/instances/' + encodeURIComponent(name) + '/' + action), {
        method: 'POST', credentials: 'same-origin',
      });
      if (!r.ok) {
        const t = await r.text().catch(() => '');
        setStatus(meta.label + ' failed', 'err');
        setNotice(meta.label + ' failed: ' + (t || ('HTTP ' + r.status)));
        return;
      }
      // CPU reset / cold start invalidates whatever SPICE was rendering;
      // reconnect to grab the new frame buffer instead of leaving a stale
      // image on screen.
      if (action !== 'stop') reconnect();
      refreshVMStatus();
    } catch (e) {
      setStatus(meta.label + ' error', 'err');
      setNotice(meta.label + ' error: ' + (e && e.message || e));
    }
  };
  if (!meta.danger) { run(); return; }
  _vgaConfirm({
    title: meta.label + ' VM',
    body:  meta.body,
    confirmLabel: meta.label,
    danger: meta.danger,
    onConfirm: run,
  });
}

// refreshVMStatus polls the Incus instance status endpoint and re-paints the
// power button label + color to match. Status names come from Incus directly
// ("Running", "Stopped", "Frozen", "Starting", "Stopping", "Error"); the
// color palette mirrors the rest of the app for consistency
// (Running=green / Stopped=grey / Error=red / transient=amber). The Start
// item is hidden when the VM is already running and the destructive entries
// are hidden when it's already stopped, so the dropdown only ever offers
// applicable actions.
let _pwrStatusTimer = null;
async function refreshVMStatus() {
  let status = 'Unknown';
  try {
    const r = await fetch(apiURL('/api/incus/instances/' + encodeURIComponent(name) + '/status'), { cache:'no-store' });
    if (r.ok) {
      const j = await r.json();
      if (j && typeof j.status === 'string' && j.status) status = j.status;
    }
  } catch(_) {}
  const btn = document.getElementById('pwr-btn');
  if (!btn) return;
  let color = '#f0b429';                    // amber default for transient/unknown
  if (status === 'Running')      color = '#3fb950';
  else if (status === 'Stopped') color = '#6e7681';
  else if (status === 'Error')   color = '#ff453a';
  btn.textContent = status;
  btn.style.color = color;
  // Toggle which dropdown entries are visible based on power state.
  const menu = document.getElementById('pwr-menu');
  if (menu) {
    const running = status === 'Running' || status === 'Frozen';
    const stopped = status === 'Stopped';
    menu.querySelectorAll('[data-pwr-action]').forEach(function(el) {
      const a = el.getAttribute('data-pwr-action');
      let show = true;
      if (a === 'start')                       show = stopped;
      else if (a === 'stop' || a === 'restart' || a === 'reset') show = running;
      el.style.display = show ? '' : 'none';
    });
  }
}
function _startPwrPolling() {
  if (_pwrStatusTimer) return;
  refreshVMStatus();
  _pwrStatusTimer = setInterval(refreshVMStatus, 5000);
}
_startPwrPolling();

// Tiny in-DOM confirm modal styled to match the rest of the VGA toolbar.
// Avoids window.confirm() (project popup convention) without pulling in
// the main app's modal stack — the VGA viewer is a standalone HTML page.
function _vgaConfirm(opts) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);'
    + 'display:flex;align-items:center;justify-content:center;z-index:9999;'
    + 'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;color:#e2e2e6;';
  const card = document.createElement('div');
  card.style.cssText = 'min-width:360px;max-width:90vw;background:#202028;'
    + 'border:1px solid #3a3a44;border-radius:6px;'
    + 'box-shadow:0 12px 40px rgba(0,0,0,0.6);overflow:hidden;';
  card.innerHTML =
      '<div style="padding:14px 18px;font-size:14px;font-weight:600;'
    +   'border-bottom:1px solid #3a3a44;background:rgba(255,138,138,0.08);">' + opts.title + '</div>'
    + '<div style="padding:16px 18px;font-size:13px;line-height:1.5;color:#cccccd;">' + opts.body + '</div>'
    + '<div style="padding:10px 14px;display:flex;justify-content:flex-end;gap:8px;background:#1a1a22;'
    +   'border-top:1px solid #3a3a44;">'
    + '  <button data-cancel  style="background:#2a2a34;color:#e2e2e6;border:1px solid #3a3a44;'
    +       'padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;">Cancel</button>'
    + '  <button data-confirm style="background:' + (opts.danger ? '#bf3a3a' : '#5a5aff') + ';color:#fff;'
    +       'border:none;padding:5px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">'
    +       (opts.confirmLabel || 'OK') + '</button>'
    + '</div>';
  wrap.appendChild(card);
  document.body.appendChild(wrap);
  const close = () => wrap.remove();
  card.querySelector('[data-cancel]').addEventListener('click', close);
  card.querySelector('[data-confirm]').addEventListener('click', () => { close(); opts.onConfirm && opts.onConfirm(); });
  // Esc cancels; Enter confirms.
  const onKey = (ev) => {
    if (ev.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); }
    if (ev.key === 'Enter')  { close(); document.removeEventListener('keydown', onKey); opts.onConfirm && opts.onConfirm(); }
  };
  document.addEventListener('keydown', onKey);
}

// Persist the chosen pointer style across reconnects and across viewer
// sessions for this VM. Stored under a key that includes the instance name
// so each VM can keep its own preference. We default to the large arrow
// because spice-html5 frequently sets cursor:none when the guest sends no
// cursor data — a custom URL cursor stays visible regardless.
const _CUR_STORE_KEY = 'znas.lxd.vga.cursor.' + name;
const _VALID_CURSORS = ['default','large','crosshair','dot','cell','hidden'];
function _readSavedCursor() {
  try {
    const v = localStorage.getItem(_CUR_STORE_KEY);
    if (_VALID_CURSORS.indexOf(v) >= 0) return v;
  } catch(_){}
  return 'large';
}
function _applyCursor(name) {
  const area = document.getElementById('spice-area');
  if (!area) return;
  _VALID_CURSORS.forEach(n => area.classList.remove('cur-' + n));
  area.classList.add('cur-' + name);
  // Highlight active item in the menu.
  document.querySelectorAll('#cur-menu .kbd-item').forEach(el => {
    el.style.background = el.dataset.cur === name ? '#3a3a3a' : '';
    el.style.color      = el.dataset.cur === name ? '#fff'    : '';
  });
}
function setCursor(name) {
  if (_VALID_CURSORS.indexOf(name) < 0) name = 'default';
  try { localStorage.setItem(_CUR_STORE_KEY, name); } catch(_){}
  _applyCursor(name);
  document.getElementById('cur-menu').style.display = 'none';
}

window.addEventListener('load', function() {
  if (embedded) document.body.setAttribute('data-embed', '');
  _applyCursor(_readSavedCursor());
  refreshCDROMState();
  connect();
});
</script>
</body>
</html>`
