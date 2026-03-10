package handlers

import (
	"net"
	"net/http"
	"zfsnas/internal/version"
)

// HandleGetVersion returns the running application version, releases URL, and server IP.
func HandleGetVersion(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{
		"version":      version.Version,
		"releases_url": version.ReleasesURL,
		"server_ip":    serverIP(),
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
