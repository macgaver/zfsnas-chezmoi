package handlers

// Firewall services (Phase 4): DHCP & DNS status and leases, WireGuard
// status and key generation.

import (
	"encoding/json"
	"net/http"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/sdn"
	"zfsnas/system"
)

func sdnUsesDnsmasq(c *sdn.Config) bool {
	if c.DNS.Enabled {
		return true
	}
	for _, d := range c.DHCP {
		if d.Enabled {
			return true
		}
	}
	return false
}

func sdnUsesDDNS(c *sdn.Config) bool {
	for _, e := range c.DDNS {
		if e.Enabled {
			return true
		}
	}
	return false
}

// HandleSDNDDNSStatus — GET /api/sdn/ddns/status → {installed, running,
// entries: {entry id: {host name: {ip, status, updated, checked}}}}
func HandleSDNDDNSStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, map[string]any{
			"installed": system.SDNDDClientInstalled(),
			"running":   system.SDNDDNSRunning(),
			"entries":   system.SDNDDNSStatus(c),
		})
	}
}

// HandleSDNIncusNetworks — GET /api/sdn/incus-networks → the Incus networks
// with their own address (host-nat), shown read-only: Incus runs their
// DHCP, DNS and NAT.
func HandleSDNIncusNetworks(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.SDNIncusNetworks())
}

// HandleSDNIfNames — GET /api/sdn/ifnames → Linux device → the name the
// admin gave its Firewall interface ({} without the Firewall). Every page
// that shows an interface uses it (dashboard charts, bridges, tables).
func HandleSDNIfNames(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := sdnStoreFor(appCfg)
		if s, _ := st.LoadState(); !s.Enabled {
			jsonOK(w, map[string]string{})
			return
		}
		c, err := st.LoadConfirmed()
		if err != nil {
			jsonOK(w, map[string]string{})
			return
		}
		jsonOK(w, c.DeviceNames())
	}
}

// HandleSDNServices — GET /api/sdn/services → tools installed, dnsmasq running.
func HandleSDNServices(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, system.SDNServicesStatus())
}

// HandleSDNLeases — GET /api/sdn/dhcp/leases → [{interface, mac, ip, hostname, expires}]
func HandleSDNLeases(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, system.SDNDHCPLeases(c))
	}
}

// HandleSDNDeleteLease — POST /api/sdn/dhcp/leases/delete {interface, mac, ip}
func HandleSDNDeleteLease(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b struct{ Interface, MAC, IP string }
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		sess := MustSession(r)
		err = system.SDNDeleteDHCPLease(c, b.Interface, b.MAC, b.IP)
		res := audit.ResultOK
		if err != nil {
			res = audit.ResultError
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionSDNApply, Target: "dhcp lease",
			Result: res, Details: "deleted lease " + b.IP + " (" + b.MAC + ")"})
		if err != nil {
			jsonErr(w, http.StatusBadRequest, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleSDNTopology — GET /api/sdn/topology: the Local Topo dashboard.
func HandleSDNTopology(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, system.SDNTopologyNow(c))
	}
}

// HandleSDNUnnamedHosts — GET /api/sdn/unnamed-hosts: the inside addresses
// no name is known for.
func HandleSDNUnnamedHosts(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, system.SDNUnnamedHosts(c))
	}
}

// HandleSDNWireGuardStatus — GET /api/sdn/wireguard/status → {tunnel id: {up, peers}}
func HandleSDNWireGuardStatus(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := sdnStoreFor(appCfg).LoadConfirmed()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		jsonOK(w, system.SDNWireGuardStatus(c))
	}
}

// HandleSDNWireGuardKeys — POST /api/sdn/wireguard/keys → a new key pair
// and preshared key for a "generate for me" peer. The private key is shown
// to the admin once (client config / QR) and never stored.
func HandleSDNWireGuardKeys(w http.ResponseWriter, r *http.Request) {
	priv, err := sdn.GenerateWGKey()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	pub, _ := sdn.WGPublicKey(priv)
	psk, err := sdn.GenerateWGPSK()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]string{"private_key": priv, "public_key": pub, "preshared_key": psk})
}
