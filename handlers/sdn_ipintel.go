package handlers

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"zfsnas/internal/geoip"
	"zfsnas/system"
)

func sdnPublicIPParam(w http.ResponseWriter, r *http.Request) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(r.URL.Query().Get("ip")))
	if err != nil || !a.Is4() || !geoip.IsPublic(a) {
		jsonErr(w, http.StatusBadRequest, "not a public IPv4 address")
		return netip.Addr{}, false
	}
	return a, true
}

// HandleSDNIPInfo — GET /api/sdn/ipinfo?ip= → the public address card
// (reverse DNS, registry, local lists; no third party is told about it).
func HandleSDNIPInfo(w http.ResponseWriter, r *http.Request) {
	if a, ok := sdnPublicIPParam(w, r); ok {
		jsonOK(w, system.SDNIPInfoFor(a))
	}
}

// HandleSDNIPExternal — GET /api/sdn/ipinfo/ext?ip=&service=greynoise|shodan|abuseipdb
// Sends the address to that service: the card asks only on a click.
func HandleSDNIPExternal(w http.ResponseWriter, r *http.Request) {
	a, ok := sdnPublicIPParam(w, r)
	if !ok {
		return
	}
	v, err := system.SDNIPExternal(r.URL.Query().Get("service"), a, system.SDNIPIntelKeysLoad())
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	jsonOK(w, v)
}

// HandleSDNIPIntelKeysGet — GET /api/sdn/ipinfo/keys → which keys are saved.
func HandleSDNIPIntelKeysGet(w http.ResponseWriter, r *http.Request) {
	k := system.SDNIPIntelKeysLoad()
	jsonOK(w, map[string]bool{"abuseipdb": k.AbuseIPDB != "", "greynoise": k.GreyNoise != ""})
}

// HandleSDNIPIntelKeysSet — PUT /api/sdn/ipinfo/keys {abuseipdb_key?, greynoise_key?}
// A field left out keeps the saved key; "" removes it.
func HandleSDNIPIntelKeysSet(w http.ResponseWriter, r *http.Request) {
	var b struct {
		AbuseIPDB *string `json:"abuseipdb_key"`
		GreyNoise *string `json:"greynoise_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	k := system.SDNIPIntelKeysLoad()
	if b.AbuseIPDB != nil {
		k.AbuseIPDB = strings.TrimSpace(*b.AbuseIPDB)
	}
	if b.GreyNoise != nil {
		k.GreyNoise = strings.TrimSpace(*b.GreyNoise)
	}
	if err := system.SDNIPIntelKeysSave(k); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	HandleSDNIPIntelKeysGet(w, r)
}
