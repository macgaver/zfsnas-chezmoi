package handlers

import (
	"net"
	"net/http"
	"os"
	"os/user"
	"zfsnas/internal/config"
	"zfsnas/internal/version"
	"zfsnas/system"
)

// HandleGetVersion returns the running application version, releases URL, server IP, and hostname.
func HandleGetVersion(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	username := "zfsnas"
	if u, err := user.Current(); err == nil && u.Username != "" {
		username = u.Username
	}
	// v6.4.28: surface the LXD-related feature flags to the frontend so
	// it can show/hide the Virtualization settings tab and the per-instance
	// Monitor tab without an extra round-trip.
	lxdMetricsEnabled := false
	mergerfsEnabled := false
	servicesEnabled := true
	serviceProxyEnabled := true
	if c, err := config.LoadAppConfig(); err == nil && c != nil {
		lxdMetricsEnabled = c.LXDMetricsEnabled
		mergerfsEnabled = c.MergerFS.Enabled
		servicesEnabled = c.ServiceDiscoveryOn()
		serviceProxyEnabled = c.ServiceProxyOn()
	}
	jsonOK(w, map[string]interface{}{
		"version":             version.Version,
		"releases_url":        version.ReleasesURL,
		"server_ip":           serverIP(),
		"hostname":            hostname,
		"username":            username,
		"experimental_mode":   version.IsExperimental(),
		"lxd_available":       system.LXDAvailable(),
		"lxd_metrics_enabled": lxdMetricsEnabled,
		"mergerfs_installed":  system.MergerFSInstalled(),
		"mergerfs_enabled":    mergerfsEnabled,
		// v6.8.1 — gates the Services tab and the in-panel embed.
		"services_enabled":       servicesEnabled,
		"service_proxy_enabled":  serviceProxyEnabled,
		// v6.5.19: changed across polls means the server restarted or was
		// upgraded — frontend shows a "Server Restarted" popup with a
		// Refresh button.
		"startup_time_unix":   version.StartedAt.Unix(),
	})
}

// serverIP returns the primary non-loopback IPv4 address.
func serverIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "localhost"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
