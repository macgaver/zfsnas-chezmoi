package handlers

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// ACL settings of datasets: the "Permissions & ACLs" section of Edit
// Dataset, the review shown after a pool from another system is imported,
// and the warnings in the SMB / NFS / VirtIO-FS editors. All three share
// system.ACLIssues so they never disagree.

// aclShareRefs lists every consumer that cares about a dataset's ACL mode:
// SMB shares (with their Windows ACL flag), NFS exports and VM VirtIO-FS
// shares. excludeSMB / excludeNFS drop the share being edited, so the editor
// can check the form's values instead of the saved ones.
func aclShareRefs(excludeSMB, excludeNFS string) []system.ACLShareRef {
	var refs []system.ACLShareRef
	cfgDir := config.Dir()
	if smb, err := system.ListSMBShares(cfgDir); err == nil {
		for _, s := range smb {
			if excludeSMB != "" && strings.EqualFold(s.Name, excludeSMB) {
				continue
			}
			refs = append(refs, system.ACLShareRef{Kind: "smb", Name: s.Name, Path: s.Path, WindowsACL: s.WindowsACL})
		}
	}
	if nfs, err := system.ListNFSShares(cfgDir); err == nil {
		for _, s := range nfs {
			if excludeNFS != "" && s.ID == excludeNFS {
				continue
			}
			refs = append(refs, system.ACLShareRef{Kind: "nfs", Name: s.Path, Path: s.Path})
		}
	}
	if system.LXDAvailable() {
		if insts, err := system.LXDListInstanceSummaries(); err == nil {
			disks := instanceDisks()
			for _, in := range insts {
				if in.Type != "virtual-machine" {
					continue
				}
				for _, dk := range disks[in.Name] {
					if dk.Pool == "" && strings.HasPrefix(dk.Source, "/") && !strings.HasPrefix(dk.Source, "/dev/") {
						refs = append(refs, system.ACLShareRef{Kind: "virtiofs", Name: in.Name, Path: dk.Source})
					}
				}
			}
		}
	}
	return refs
}

// aclProtect says why a child must keep its mode when its parent switches
// to preset: a share on it needs the mode it has.
func aclProtect(preset string, use map[string][]system.ACLShareRef) func(system.DatasetACL) string {
	return func(d system.DatasetACL) string {
		for _, u := range use[d.Name] {
			if u.Kind == "smb" && u.WindowsACL && preset != system.PresetNFSv4 && d.Preset == system.PresetNFSv4 {
				return "SMB share \"" + u.Name + "\" uses Windows ACL"
			}
			if u.Kind == "virtiofs" && preset != system.PresetPOSIX && d.Preset == system.PresetPOSIX {
				return "VM " + u.Name + " uses it over VirtIO-FS"
			}
		}
		return ""
	}
}

type aclDatasetView struct {
	system.DatasetACL
	Use     []system.ACLShareRef `json:"use"`
	Issues  []system.ACLIssue    `json:"issues"`
	Suggest string               `json:"suggest,omitempty"`
}

func aclViews(tree []system.DatasetACL, refs []system.ACLShareRef) ([]aclDatasetView, map[string][]system.ACLShareRef) {
	mounts := system.MountMap()
	use := map[string][]system.ACLShareRef{}
	views := make([]aclDatasetView, len(tree))
	for i, d := range tree {
		u := system.ACLUsageFor(d, refs, mounts)
		use[d.Name] = u
		is := system.ACLIssues(d, u)
		views[i] = aclDatasetView{DatasetACL: d, Use: u, Issues: is, Suggest: system.SuggestedPreset(is)}
		if views[i].Use == nil {
			views[i].Use = []system.ACLShareRef{}
		}
		if views[i].Issues == nil {
			views[i].Issues = []system.ACLIssue{}
		}
	}
	return views, use
}

// HandleGetDatasetACL — GET /api/dataset-acl/{path}
// The dataset's ACL settings, who uses it, its issues, and its children
// (for the "also apply to child datasets" preview).
func HandleGetDatasetACL(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["path"]
	tree, err := system.ACLTree(name, replicationDestinations())
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	views, _ := aclViews(tree, aclShareRefs("", ""))
	jsonOK(w, map[string]interface{}{
		"dataset":  views[0],
		"children": views[1:],
	})
}

// HandleSetDatasetACL — PUT /api/dataset-acl/{path}  {preset, recursive}
func HandleSetDatasetACL(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["path"]
	var req struct {
		Preset    string `json:"preset"`
		Recursive bool   `json:"recursive"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tree, err := system.ACLTree(name, replicationDestinations())
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, use := aclViews(tree, aclShareRefs("", ""))
	plan, err := system.PlanACLChange(tree, req.Preset, req.Recursive, aclProtect(req.Preset, use))
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	applyErr := system.ApplyACLChange(name, plan)

	details := "preset " + req.Preset
	if req.Recursive {
		details += ", " + itoa(len(plan.Follow)) + " child datasets follow"
	}
	if len(plan.Pin) > 0 {
		details += ", " + itoa(len(plan.Pin)) + " kept as they were"
	}
	res := audit.ResultOK
	if applyErr != nil {
		res = audit.ResultError
		details += ": " + applyErr.Error()
	}
	sess := MustSession(r)
	audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionUpdateDataset,
		Target: name, Result: res, Details: "ACL settings: " + details})
	if applyErr != nil {
		jsonErr(w, http.StatusInternalServerError, applyErr.Error())
		return
	}
	tree, _ = system.ACLTree(name, replicationDestinations())
	views, _ := aclViews(tree, aclShareRefs("", ""))
	jsonOK(w, map[string]interface{}{"plan": plan, "dataset": views[0], "children": views[1:]})
}

// aclReview finds the datasets of pool with errors or warnings. Info-level
// findings (xattr) are listed but never raise the banner.
func aclReview(pool string) (items []aclDatasetView, sig string, err error) {
	tree, err := system.ACLTree(pool, replicationDestinations())
	if err != nil {
		return nil, "", err
	}
	views, _ := aclViews(tree, aclShareRefs("", ""))
	var keys []string
	for _, v := range views {
		if v.Skip != "" || v.Suggest == "" {
			continue
		}
		items = append(items, v)
		for _, is := range v.Issues {
			if is.Level != "info" {
				keys = append(keys, v.Name+":"+is.Code)
			}
		}
	}
	if len(keys) == 0 {
		return items, "", nil
	}
	return items, system.ReviewSignature(keys), nil
}

// HandlePoolACLReview — GET /api/pool/acl-review?pool=
func HandlePoolACLReview(w http.ResponseWriter, r *http.Request) {
	pool := r.URL.Query().Get("pool")
	if pool == "" || strings.Contains(pool, "/") {
		jsonErr(w, http.StatusBadRequest, "pool required")
		return
	}
	items, sig, err := aclReview(pool)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if items == nil {
		items = []aclDatasetView{}
	}
	jsonOK(w, map[string]interface{}{
		"pool":      pool,
		"items":     items,
		"signature": sig,
		"dismissed": sig != "" && system.GetReviewDismissed(pool) == sig,
	})
}

// HandlePoolACLReviewDismiss — POST /api/pool/acl-review/dismiss {pool, signature}
// Hides the banner until the findings change.
func HandlePoolACLReviewDismiss(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool      string `json:"pool"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pool == "" || strings.Contains(req.Pool, "/") {
		jsonErr(w, http.StatusBadRequest, "pool required")
		return
	}
	if len(req.Signature) != 16 || strings.Trim(req.Signature, "0123456789abcdef") != "" {
		jsonErr(w, http.StatusBadRequest, "invalid signature")
		return
	}
	if err := system.SetReviewDismissed(req.Pool, req.Signature); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleACLCheck — GET /api/acl-check?path=&use=smb|nfs|virtiofs&windows_acl=1&exclude_smb=&exclude_nfs=&vm=
// What the share editors show under the path: the issues the dataset under
// path would have once this share is saved.
func HandleACLCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	path := strings.TrimSpace(q.Get("path"))
	if !strings.HasPrefix(path, "/") {
		jsonOK(w, map[string]interface{}{"dataset": "", "issues": []system.ACLIssue{}})
		return
	}
	mounts := system.MountMap()
	ds := system.ResolveDatasetByPath(mounts, path)
	if ds == "" {
		jsonOK(w, map[string]interface{}{"dataset": "", "issues": []system.ACLIssue{}})
		return
	}
	tree, err := system.ACLTree(ds, nil)
	if err != nil || len(tree) == 0 {
		jsonOK(w, map[string]interface{}{"dataset": ds, "issues": []system.ACLIssue{}})
		return
	}
	d := tree[0]
	refs := aclShareRefs(q.Get("exclude_smb"), q.Get("exclude_nfs"))
	if vm := q.Get("vm"); vm != "" {
		// The VM editor sends every VirtIO-FS row; drop the saved ones of
		// this VM so removed rows stop counting.
		kept := refs[:0]
		for _, x := range refs {
			if !(x.Kind == "virtiofs" && x.Name == vm) {
				kept = append(kept, x)
			}
		}
		refs = kept
	}
	me := system.ACLShareRef{Kind: q.Get("use"), Name: q.Get("name"), Path: path, WindowsACL: q.Get("windows_acl") == "1"}
	if me.Name == "" {
		me.Name = "this share"
	}
	refs = append(refs, me)
	// Saving an SMB share with Windows ACL on writes the NFSv4 preset on the
	// dataset itself (SetWindowsACLDatasetProps): judge the result, not the
	// current state, so the editor does not warn about what saving fixes.
	if me.Kind == "smb" && me.WindowsACL && mounts[strings.TrimRight(path, "/")] == ds {
		for k, v := range map[string]string{"acltype": "nfsv4", "aclinherit": "passthrough", "aclmode": "passthrough", "xattr": "sa"} {
			d.Props[k] = system.ACLProp{Value: v, Source: "local"}
		}
		d.Preset = system.PresetNFSv4
	}
	issues := system.ACLIssues(d, system.ACLUsageFor(d, refs, mounts))
	// Only what this share is involved in; other findings belong to the
	// dataset page.
	var mine []system.ACLIssue
	for _, is := range issues {
		if is.Level == "info" {
			continue
		}
		switch is.Code {
		case "virtiofs-needs-posix":
			if me.Kind == "virtiofs" || (me.Kind == "smb" && me.WindowsACL) {
				mine = append(mine, is)
			}
		case "windows-acl-mismatch":
			if me.Kind == "smb" && me.WindowsACL || me.Kind == "virtiofs" {
				mine = append(mine, is)
			}
		case "nfsv4-unused":
			// Already said by the VirtIO-FS error.
			if me.Kind != "virtiofs" {
				mine = append(mine, is)
			}
		default:
			mine = append(mine, is)
		}
	}
	if mine == nil {
		mine = []system.ACLIssue{}
	}
	sort.SliceStable(mine, func(i, j int) bool { return mine[i].Level == "error" && mine[j].Level != "error" })
	jsonOK(w, map[string]interface{}{"dataset": ds, "preset": d.Preset, "issues": mine, "suggest": system.SuggestedPreset(mine)})
}

func itoa(n int) string { return strconv.Itoa(n) }
