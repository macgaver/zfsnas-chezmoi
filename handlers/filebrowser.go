package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleFileBrowserList lists the contents of a directory within a validated root.
// GET /api/files/list?root=<base64url>&subpath=<relative>
func HandleFileBrowserList(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("root")
	if token == "" {
		jsonErr(w, http.StatusBadRequest, "missing root parameter")
		return
	}
	subpath := r.URL.Query().Get("subpath")

	knownRoots, err := system.ResolveKnownRoots(config.Dir())
	if err != nil && len(knownRoots) == 0 {
		jsonErr(w, http.StatusInternalServerError, "could not resolve known roots")
		return
	}
	absRoot, label, err := system.ValidateRootToken(token, knownRoots)
	if err != nil {
		jsonErr(w, http.StatusForbidden, err.Error())
		return
	}

	result, err := system.ListDir(absRoot, subpath, label)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, result)
}

// HandleFileBrowserUsersGroups returns system user and group name lists.
// GET /api/files/users-groups          — filtered (root + uid/gid ≥ 1000 + sambashare)
// GET /api/files/users-groups?all=true — all entries unfiltered
func HandleFileBrowserUsersGroups(w http.ResponseWriter, r *http.Request) {
	var users []system.UserEntry
	var groups []system.GroupEntry
	var err error
	if r.URL.Query().Get("all") == "true" {
		users, groups, err = system.GetAllSystemUsersGroups()
	} else {
		users, groups, err = system.GetSystemUsersGroups()
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"users":  users,
		"groups": groups,
	})
}

// HandleFileBrowserChown changes ownership of a file or directory.
// POST /api/files/chown (admin only)
func HandleFileBrowserChown(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root      string `json:"root"`
		Subpath   string `json:"subpath"`
		Owner     string `json:"owner"`
		Group     string `json:"group"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Owner == "" || req.Group == "" {
		jsonErr(w, http.StatusBadRequest, "owner and group are required")
		return
	}

	knownRoots, err := system.ResolveKnownRoots(config.Dir())
	if err != nil && len(knownRoots) == 0 {
		jsonErr(w, http.StatusInternalServerError, "could not resolve known roots")
		return
	}
	absRoot, _, err := system.ValidateRootToken(req.Root, knownRoots)
	if err != nil {
		jsonErr(w, http.StatusForbidden, err.Error())
		return
	}
	absPath, err := system.SafeJoin(absRoot, req.Subpath)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := system.ChownPath(absPath, req.Owner, req.Group, req.Recursive); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	details := "chown " + req.Owner + ":" + req.Group + " " + absPath
	if req.Recursive {
		details += " [recursive]"
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserChown,
		Target:  absPath,
		Result:  audit.ResultOK,
		Details: details,
	})

	jsonOK(w, map[string]bool{"ok": true})
}

// HandleFileBrowserChmod changes permissions of a file or directory.
// POST /api/files/chmod (admin only)
func HandleFileBrowserChmod(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root      string `json:"root"`
		Subpath   string `json:"subpath"`
		Mode      string `json:"mode"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Mode == "" {
		jsonErr(w, http.StatusBadRequest, "mode is required")
		return
	}

	knownRoots, err := system.ResolveKnownRoots(config.Dir())
	if err != nil && len(knownRoots) == 0 {
		jsonErr(w, http.StatusInternalServerError, "could not resolve known roots")
		return
	}
	absRoot, _, err := system.ValidateRootToken(req.Root, knownRoots)
	if err != nil {
		jsonErr(w, http.StatusForbidden, err.Error())
		return
	}
	absPath, err := system.SafeJoin(absRoot, req.Subpath)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := system.ChmodPath(absPath, req.Mode, req.Recursive); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	details := "chmod " + req.Mode + " " + absPath
	if req.Recursive {
		details += " [recursive]"
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserChmod,
		Target:  absPath,
		Result:  audit.ResultOK,
		Details: details,
	})

	jsonOK(w, map[string]bool{"ok": true})
}

// ── v6.5.29 — Browse Files becomes a real browser ────────────────────────────

// fbResolveRoot does the common upfront work: pulls the root token out
// of the query/body, looks up knownRoots, and returns (absRoot, label)
// on success. Writes the error to `w` and returns ("", "", false) on
// failure so the caller can `return` immediately.
func fbResolveRoot(w http.ResponseWriter, token string) (string, string, bool) {
	knownRoots, err := system.ResolveKnownRoots(config.Dir())
	if err != nil && len(knownRoots) == 0 {
		jsonErr(w, http.StatusInternalServerError, "could not resolve known roots")
		return "", "", false
	}
	absRoot, label, err := system.ValidateRootToken(token, knownRoots)
	if err != nil {
		jsonErr(w, http.StatusForbidden, err.Error())
		return "", "", false
	}
	return absRoot, label, true
}

// HandleFileBrowserRoots returns every dataset mountpoint + share root
// the FE is allowed to address. Used by the left-pane multi-root tree:
// the modal opens at one root, but the user can navigate to / copy /
// move between any of them. Each entry carries the same base64url
// root token the other endpoints expect, sorted by label for a stable
// display order. v6.5.29.
// GET /api/files/roots
func HandleFileBrowserRoots(w http.ResponseWriter, r *http.Request) {
	known, err := system.ResolveKnownRoots(config.Dir())
	if err != nil && len(known) == 0 {
		jsonErr(w, http.StatusInternalServerError, "could not resolve known roots")
		return
	}
	type rootEntry struct {
		Label   string `json:"label"`
		Token   string `json:"token"`
		AbsPath string `json:"abs_path"`
	}
	out := make([]rootEntry, 0, len(known))
	for abs, label := range known {
		out = append(out, rootEntry{
			Label:   label,
			Token:   base64.RawURLEncoding.EncodeToString([]byte(abs)),
			AbsPath: abs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	jsonOK(w, map[string]interface{}{"roots": out})
}

// HandleFileBrowserTree returns the folder tree for the left pane.
// GET /api/files/tree?root=<b64>&subpath=&depth=1
func HandleFileBrowserTree(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("root")
	if token == "" {
		jsonErr(w, http.StatusBadRequest, "missing root parameter")
		return
	}
	absRoot, label, ok := fbResolveRoot(w, token)
	if !ok {
		return
	}
	subpath := r.URL.Query().Get("subpath")
	depth := 1
	if d, err := strconv.Atoi(r.URL.Query().Get("depth")); err == nil && d >= 0 {
		depth = d
	}
	tree, err := system.WalkTree(absRoot, subpath, depth)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]interface{}{
		"root_label": label,
		"tree":       tree,
	})
}

// HandleFileBrowserMkdir creates a new folder.
// POST /api/files/mkdir  body: {root, subpath, name}
func HandleFileBrowserMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root    string `json:"root"`
		Subpath string `json:"subpath"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	absRoot, _, ok := fbResolveRoot(w, req.Root)
	if !ok {
		return
	}
	if err := system.MakeDir(absRoot, req.Subpath, req.Name); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserMkdir,
		Target:  filepath.Join(absRoot, req.Subpath, req.Name),
		Result:  audit.ResultOK,
		Details: "mkdir " + req.Name,
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleFileBrowserUpload streams an uploaded file into root/subpath.
// It uses a streaming multipart reader (flat memory regardless of file
// size) so the leading text fields — root, subpath, relpath, overwrite —
// MUST be appended to the FormData before the file part. Exactly one
// file part is expected per request; the FE uploads one file at a time
// so it can pair each file with its own relpath (folder drops) and
// surface per-file overwrite prompts.
// POST /api/files/upload  (multipart/form-data)
func HandleFileBrowserUpload(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "expected multipart/form-data")
		return
	}
	fields := map[string]string{}
	uploaded := 0
	var lastAbs string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "read upload: "+err.Error())
			return
		}
		// Text fields (no filename) carry the upload parameters; cap the
		// read so a malformed client can't stream an unbounded "field".
		if part.FileName() == "" {
			buf, _ := io.ReadAll(io.LimitReader(part, 1<<20))
			fields[part.FormName()] = string(buf)
			part.Close()
			continue
		}
		absRoot, _, ok := fbResolveRoot(w, fields["root"])
		if !ok {
			return
		}
		name := fields["relpath"]
		if name == "" {
			name = part.FileName()
		}
		overwrite := fields["overwrite"] == "true"
		if err := system.UploadFile(absRoot, fields["subpath"], name, overwrite, part); err != nil {
			part.Close()
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		part.Close()
		uploaded++
		lastAbs = filepath.Join(absRoot, fields["subpath"], filepath.FromSlash(name))
	}
	if uploaded == 0 {
		jsonErr(w, http.StatusBadRequest, "no file in upload")
		return
	}
	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserUpload,
		Target:  lastAbs,
		Result:  audit.ResultOK,
		Details: "upload " + filepath.Base(lastAbs),
	})
	jsonOK(w, map[string]interface{}{"ok": true, "uploaded": uploaded})
}

// HandleFileBrowserDelete removes one or more entries.
// POST /api/files/delete  body: {root, subpaths[], recursive}
func HandleFileBrowserDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root      string   `json:"root"`
		Subpaths  []string `json:"subpaths"`
		Recursive bool     `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	absRoot, _, ok := fbResolveRoot(w, req.Root)
	if !ok {
		return
	}
	if err := system.RemovePaths(absRoot, req.Subpaths, req.Recursive); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	first := ""
	if len(req.Subpaths) > 0 {
		first = req.Subpaths[0]
	}
	details := fmt.Sprintf("rm %d path(s)", len(req.Subpaths))
	if len(req.Subpaths) <= 5 {
		details += ": " + strings.Join(req.Subpaths, ", ")
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserDelete,
		Target:  filepath.Join(absRoot, first),
		Result:  audit.ResultOK,
		Details: details,
	})
	jsonOK(w, map[string]interface{}{"ok": true, "removed": len(req.Subpaths)})
}

// HandleFileBrowserMove / Copy share the same request shape.
type fbMoveCopyReq struct {
	SrcRoot     string   `json:"src_root"`
	SrcSubpaths []string `json:"src_subpaths"`
	DstRoot     string   `json:"dst_root"`
	DstSubpath  string   `json:"dst_subpath"`
	Overwrite   bool     `json:"overwrite"`
}

// HandleFileBrowserMove moves entries (across roots when both are
// knownRoots).
// POST /api/files/move
func HandleFileBrowserMove(w http.ResponseWriter, r *http.Request) {
	fbStartTransfer(w, r, "move")
}

// fbStartTransfer backs both /api/files/copy and /api/files/move.
//
// Validation is synchronous, so a bad request still fails the POST and the
// frontend's overwrite-confirm flow is unaffected. Past that the work runs as a
// background job and the response carries a job id the client polls — a 69 GB
// copy used to hold this request open for an hour with no progress and no way
// to cancel it.
//
// Three response shapes:
//
//	{"ok":true,"done":true}          same-filesystem move, already finished
//	{"ok":true,"job_id":"fbt-…"}     transfer running in the background
//	{"error":"…"}                    validation failed, nothing started
func fbStartTransfer(w http.ResponseWriter, r *http.Request, op string) {
	var req fbMoveCopyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	srcAbs, _, ok := fbResolveRoot(w, req.SrcRoot)
	if !ok {
		return
	}
	dstAbs, _, ok := fbResolveRoot(w, req.DstRoot)
	if !ok {
		return
	}

	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	target := filepath.Join(dstAbs, req.DstSubpath)
	action := audit.ActionFileBrowserCopy
	verb := "cp -a"
	if op == "move" {
		action = audit.ActionFileBrowserMove
		verb = "mv"
	}

	// Audit at completion rather than at kickoff: the outcome is only known when
	// the job ends, and a transfer can now be cancelled or fail long after this
	// request returned.
	onFinish := func(j *system.FbTransferJob) {
		result := audit.ResultOK
		if j.Status != "done" {
			result = audit.ResultError
		}
		details := fmt.Sprintf("%s %d → %s (%s, %s)", verb, len(req.SrcSubpaths), target, j.Engine, j.Status)
		if j.Error != "" {
			details += ": " + j.Error
		}
		audit.Log(audit.Entry{
			User:    user,
			Action:  action,
			Target:  target,
			Result:  result,
			Details: details,
		})
	}

	job, err := system.StartFbTransfer(op, srcAbs, req.SrcSubpaths, dstAbs, req.DstSubpath, req.Overwrite, onFinish)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if job == nil {
		// Same-filesystem move: an instant rename, already done. Audited inline
		// because no job exists to report an outcome later.
		audit.Log(audit.Entry{
			User:    user,
			Action:  action,
			Target:  target,
			Result:  audit.ResultOK,
			Details: fmt.Sprintf("%s %d → %s (rename)", verb, len(req.SrcSubpaths), target),
		})
		jsonOK(w, map[string]interface{}{"ok": true, "done": true})
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "job_id": job.ID})
}

// HandleFbTransferProgress returns one transfer job's state.
// GET /api/files/transfers/{id}/progress
func HandleFbTransferProgress(w http.ResponseWriter, r *http.Request) {
	job := system.FbTransferByID(mux.Vars(r)["id"])
	if job == nil {
		jsonErr(w, http.StatusNotFound, "unknown transfer")
		return
	}
	jsonOK(w, job.Snapshot())
}

// HandleFbTransferCancel stops a running transfer.
// POST /api/files/transfers/{id}/cancel
func HandleFbTransferCancel(w http.ResponseWriter, r *http.Request) {
	job := system.FbTransferByID(mux.Vars(r)["id"])
	if job == nil {
		jsonErr(w, http.StatusNotFound, "unknown transfer")
		return
	}
	job.Cancel()
	jsonOK(w, map[string]interface{}{"ok": true})
}

// HandleFileBrowserRename renames a single entry in place.
// POST /api/files/rename
func HandleFileBrowserRename(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root    string `json:"root"`
		Subpath string `json:"subpath"`
		NewName string `json:"new_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	absRoot, _, ok := fbResolveRoot(w, req.Root)
	if !ok {
		return
	}
	if err := system.RenamePath(absRoot, req.Subpath, req.NewName); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, _ := SessionFromRequest(r)
	user := ""
	if sess != nil {
		user = sess.Username
	}
	audit.Log(audit.Entry{
		User:    user,
		Action:  audit.ActionFileBrowserMove,
		Target:  filepath.Join(absRoot, filepath.Dir(req.Subpath), req.NewName),
		Result:  audit.ResultOK,
		Details: "rename " + req.Subpath + " → " + req.NewName,
	})
	jsonOK(w, map[string]interface{}{"ok": true})
}

// HandleFileBrowserCopy copies entries (cross-root OK) as a background job.
// POST /api/files/copy
func HandleFileBrowserCopy(w http.ResponseWriter, r *http.Request) {
	fbStartTransfer(w, r, "copy")
}

// HandleFileBrowserDownload streams an arbitrary file with
// `Content-Disposition: attachment` so the browser saves it instead of
// previewing it. Unlike /api/files/raw, this endpoint has no MIME
// allowlist — downloads of any byte content are legitimate. SafeJoin
// still constrains the path to knownRoots so a session can't fetch
// /etc/shadow.
// GET /api/files/download?root=<b64>&subpath=<rel>
func HandleFileBrowserDownload(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("root")
	if token == "" {
		http.Error(w, "missing root", http.StatusBadRequest)
		return
	}
	absRoot, _, ok := fbResolveRoot(w, token)
	if !ok {
		return
	}
	subpath := r.URL.Query().Get("subpath")
	abs, err := system.SafeJoin(absRoot, subpath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Same sudo stat / cat pattern the raw endpoint uses — works
	// inside traverse-denied parents (root:root 0770 datasets etc.).
	out, err := exec.Command("sudo", "stat", "-c", "%s %Y %F", abs).Output()
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 3 {
		http.Error(w, "stat parse", http.StatusInternalServerError)
		return
	}
	size, _ := strconv.ParseInt(parts[0], 10, 64)
	ftype := strings.Join(parts[2:], " ")
	if strings.Contains(ftype, "directory") {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	name := filepath.Base(abs)
	// Content-Disposition: a quoted filename + the modern * form so
	// browsers handle non-ASCII names correctly.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+strings.ReplaceAll(name, `"`, `\"`)+`"; filename*=UTF-8''`+urlQueryEscape(name))
	cmd := exec.Command("sudo", "cat", abs)
	cmd.Stdout = w
	cmd.Run() //nolint:errcheck
}

// urlQueryEscape is the percent-encoding the RFC 5987 `filename*` form
// expects (different rule than url.QueryEscape, which leaves '/' alone).
func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// fbRawAllowedMIMEs is the allowlist of MIME prefixes /api/files/raw
// will stream. Anything else → 415. We don't want this becoming an
// arbitrary file server — the allowlist is exactly the preview surface
// the FE supports (thumbnails / image viewer / future text + PDF
// preview).
var fbRawAllowedMIMEs = []string{
	"image/",
	"text/",
	"application/pdf",
}

// HandleFileBrowserRaw streams the bytes of one file. SafeJoin-validated
// + MIME-allowlisted. We can't use os.Open directly because many dataset
// mountpoints are owned root:root mode 0770 — the zfsnas service user
// lacks traverse permission, so the existing chown/chmod/list paths all
// shell through sudo. Raw does the same: `sudo head -c 512` for the
// MIME sniff, `sudo stat` for the size + mtime headers, then
// `sudo cat` to stream the body. Range-handling is left to a future
// release (browsers tolerate full responses for images; big-photo
// viewers don't need partial fetches at the scale we ship).
// GET /api/files/raw?root=<b64>&subpath=
func HandleFileBrowserRaw(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("root")
	if token == "" {
		http.Error(w, "missing root", http.StatusBadRequest)
		return
	}
	absRoot, _, ok := fbResolveRoot(w, token)
	if !ok {
		return
	}
	subpath := r.URL.Query().Get("subpath")
	abs, err := system.SafeJoin(absRoot, subpath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Stat first so we know it exists, isn't a directory, and can set
	// Content-Length + Last-Modified. `sudo stat -c '%s %Y %F'` keeps
	// the output parser trivial.
	out, err := exec.Command("sudo", "stat", "-c", "%s %Y %F", abs).Output()
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	parts := strings.Fields(strings.TrimSpace(string(out)))
	if len(parts) < 3 {
		http.Error(w, "stat parse", http.StatusInternalServerError)
		return
	}
	size, _ := strconv.ParseInt(parts[0], 10, 64)
	mtimeUnix, _ := strconv.ParseInt(parts[1], 10, 64)
	// parts[2..] is the file type ("regular file", "directory", …).
	ftype := strings.Join(parts[2:], " ")
	if strings.Contains(ftype, "directory") {
		http.Error(w, "is a directory", http.StatusBadRequest)
		return
	}
	// MIME sniff from the first 512 B via sudo head.
	sniff, err := exec.Command("sudo", "head", "-c", "512", abs).Output()
	if err != nil {
		http.Error(w, "read failed", http.StatusInternalServerError)
		return
	}
	mime := http.DetectContentType(sniff)
	allowed := false
	for _, pfx := range fbRawAllowedMIMEs {
		if strings.HasPrefix(mime, pfx) {
			allowed = true
			break
		}
	}
	if !allowed {
		http.Error(w, "file type not previewable", http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("Last-Modified", time.Unix(mtimeUnix, 0).UTC().Format(time.RFC1123))
	// SecurityHeaders middleware sets X-Frame-Options: DENY for every
	// response, which kills the in-modal PDF preview (Chrome refuses
	// to display the file in our same-origin iframe). Override to
	// SAMEORIGIN for raw previews so the file browser can embed them
	// — still blocks cross-origin framing.
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	// Stream the body. `sudo cat` is the minimal-overhead path — one
	// fork per request, output piped straight to the response writer.
	cmd := exec.Command("sudo", "cat", abs)
	cmd.Stdout = w
	if err := cmd.Run(); err != nil {
		// Headers are already sent at this point; nothing we can do
		// except log. http.Server will reset the connection.
		return
	}
}
