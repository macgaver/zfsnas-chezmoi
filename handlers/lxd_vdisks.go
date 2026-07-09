package handlers

// lxd_vdisks.go — v6.7.7 Datastore → "Virtual Disks" tab.
//
// GET /api/incus/storage-pools/{name}/vdisks returns every zvol living under
// the datastore's backing ZFS dataset, with size/usage/compression, creation
// + newest-snapshot times, and the VM/container the disk is attached to (if
// any). Association is resolved server-side from the instances' disk devices
// so it also covers raw /dev/zvol attachments, which the topology map skips.

import (
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"zfsnas/system"
)

type vdiskRow struct {
	Name      string `json:"name"`      // full zfs path
	Leaf      string `json:"leaf"`      // display name (last path segment)
	SizeBytes uint64 `json:"size"`      // configured volsize
	UsedBytes uint64 `json:"used"`      // consumed on pool
	CompRatio string `json:"comp_ratio"`
	Creation  int64  `json:"creation"`  // unix seconds
	LastSnap  int64  `json:"last_snap"` // newest snapshot creation; 0 = none
	DevPath   string `json:"dev_path"`
	Instance  string `json:"instance,omitempty"`  // attached VM/CT ("" = unattached)
	InstType  string `json:"inst_type,omitempty"` // "vm" | "container"
	InstDev   string `json:"inst_dev,omitempty"`  // device name on the instance
	RootDisk  bool   `json:"root_disk,omitempty"` // instance root disk
}

// HandleDatastoreVDisks — GET /api/lxd/storage-pools/{name}/vdisks
func HandleDatastoreVDisks(w http.ResponseWriter, r *http.Request) {
	poolName := mux.Vars(r)["name"]
	source := ""
	for _, sp := range mustStoragePools() {
		if sp.Name == poolName {
			source = sp.Source
			break
		}
	}
	if source == "" {
		jsonErr(w, http.StatusNotFound, "datastore not found or not ZFS-backed")
		return
	}

	zvols, err := system.ListAllZVols()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := []vdiskRow{}
	byName := map[string]*vdiskRow{}
	dsByName := map[string]string{}
	for _, zv := range zvols {
		if !strings.HasPrefix(zv.Name, source+"/") {
			continue
		}
		leaf := zv.Name[strings.LastIndex(zv.Name, "/")+1:]
		rows = append(rows, vdiskRow{
			Name: zv.Name, Leaf: leaf, SizeBytes: zv.Size, UsedBytes: zv.Used,
			CompRatio: zv.CompRatio, Creation: zv.Creation, DevPath: zv.DevPath,
		})
		dsByName[zv.Name] = zv.Name
	}
	for i := range rows {
		byName[rows[i].Name] = &rows[i]
	}

	// Newest snapshot per zvol — one recursive listing for the whole subtree.
	if out, err := exec.Command("sudo", "zfs", "list", "-t", "snapshot",
		"-H", "-p", "-o", "name,creation", "-r", source).Output(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Split(line, "\t")
			if len(f) < 2 {
				continue
			}
			ds := f[0][:strings.IndexByte(f[0]+"@", '@')]
			row, ok := byName[ds]
			if !ok {
				continue
			}
			if t, err := strconv.ParseInt(f[1], 10, 64); err == nil && t > row.LastSnap {
				row.LastSnap = t
			}
		}
	}

	// Attach associations from every instance's disk devices.
	disks := instanceDisks()
	if insts, err := system.LXDListInstanceSummaries(); err == nil {
		for _, in := range insts {
			typ := "container"
			if in.Type == "virtual-machine" {
				typ = "vm"
			}
			for _, dk := range disks[in.Name] {
				var cand string
				root := false
				switch {
				case strings.HasPrefix(dk.Source, "/dev/zvol/"):
					// Raw zvol attachment (ExistingDisks flow).
					cand = strings.TrimPrefix(dk.Source, "/dev/zvol/")
				case dk.Path == "/" && typ == "vm":
					cand = source + "/virtual-machines/" + in.Name + ".block"
					root = true
				case dk.Source != "" && dk.Pool != "":
					// Pool-managed custom volume.
					cand = findCustomVol(dsByName, source, dk.Source)
				}
				if row, ok := byName[cand]; ok && cand != "" {
					row.Instance = in.Name
					row.InstType = typ
					row.InstDev = dk.Device
					row.RootDisk = root
				}
			}
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	jsonOK(w, rows)
}
