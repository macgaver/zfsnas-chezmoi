package handlers

import (
	"net/http"

	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/system"
)

// HandleGetDiskIO returns the latest disk I/O snapshot for the pool's member disks.
func HandleGetDiskIO(w http.ResponseWriter, r *http.Request) {
	snap := system.GetDiskIOSnapshot()
	if snap == nil {
		jsonOK(w, map[string]interface{}{"devices": map[string]interface{}{}})
		return
	}
	jsonOK(w, snap)
}

// HandleGetGatewayNet returns the gateway's live traffic (Network Focus
// top headers), named as the admin named its Firewall interface.
func HandleGetGatewayNet(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var c *sdn.Config
		st := sdnStoreFor(appCfg)
		if s, _ := st.LoadState(); s.Enabled {
			c, _ = st.LoadConfirmed()
		}
		jsonOK(w, gatewayNetNamed(system.GetGatewayNet(), c))
	}
}

func gatewayNetNamed(g system.GatewayNet, c *sdn.Config) system.GatewayNet {
	if c != nil {
		g.Name = c.InterfaceNameByDevice(g.Iface)
	}
	return g
}

// HandleGetCpuProcs returns the latest per-process CPU usage snapshot.
func HandleGetCpuProcs(w http.ResponseWriter, r *http.Request) {
	snap := system.GetCpuProcsSnapshot()
	if snap == nil {
		jsonOK(w, map[string]interface{}{
			"smb_pct": 0, "nfs_pct": 0, "zfs_pct": 0, "minio_pct": 0, "iscsi_pct": 0,
			"vm_pct": 0, "container_pct": 0, "other_pct": 0,
			"top_procs": []interface{}{},
		})
		return
	}
	jsonOK(w, snap)
}

// HandleGetMemProcs returns the latest per-process memory usage snapshot.
func HandleGetMemProcs(w http.ResponseWriter, r *http.Request) {
	snap := system.GetMemProcsSnapshot()
	if snap == nil {
		jsonOK(w, map[string]interface{}{
			"smb_pct": 0, "nfs_pct": 0, "zfs_pct": 0, "minio_pct": 0, "iscsi_pct": 0,
			"vm_pct": 0, "container_pct": 0, "other_pct": 0,
			"arc_mb": 0, "total_mb": 0, "used_mb": 0,
			"top_procs": []interface{}{},
		})
		return
	}
	jsonOK(w, snap)
}
