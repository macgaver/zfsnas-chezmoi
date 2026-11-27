package system

// Auto groups (6.11.27) — the host side: where each list comes from, the
// boot cache, and the daily refresh of the live nft sets. The catalog, the
// IDS rule parser and the compile side are in internal/sdn/autogroups.go.
//
// Sources:
//   - firewall lists: <stats>/geo/reputation/<list>.txt, downloaded daily
//     with the location database (SDNUpdateRepLists);
//   - IDS lists: <ids dir>/rules/suricata.rules, rebuilt by SDNIDSUpdate.
//
// A list a rule uses is copied into config/sdn/autogroup-cache.json at
// every apply and refresh, so the boot unit can compile it before the pool
// that holds the statistics is mounted (same idea as the country cache).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

// SDNAutoGroupInfo is one card on Groups & countries → Auto groups.
type SDNAutoGroupInfo struct {
	sdn.AutoGroupDef
	Available bool      `json:"available"` // the list is on disk (live source)
	Entries   int       `json:"entries"`   // after cleaning
	Removed   int       `json:"removed"`   // private/reserved/duplicate entries dropped
	Updated   time.Time `json:"updated,omitempty"`
	// Present: an IDS group whose rules are in the current rule file.
	Present bool `json:"present"`
	// Note: a short state the card shows (IDS off, not downloaded yet…).
	Note string `json:"note,omitempty"`
	// Cached: not available live, the boot cache still has this list.
	Cached bool `json:"cached,omitempty"`
}

func autoGroupCachePath(configDir string) string {
	return filepath.Join(configDir, "sdn", "autogroup-cache.json")
}

// sdnAutoPaths returns the firewall-list directory and the IDS rule file of
// the confirmed configuration, and whether the IDS runs.
func sdnAutoPaths(configDir string) (repDir, idsRules string, idsOn bool) {
	st := sdn.Store{Dir: configDir}
	c, err := st.LoadConfirmed()
	if err != nil || c == nil {
		c = &sdn.Config{}
	}
	dir, _ := sdnStatsDir(c)
	return SDNRepDir(SDNGeoDir(dir)), filepath.Join(sdnIDSPaths(c).RulesDir, "suricata.rules"), c.IDSRuns()
}

// IDS rule file → parsed lists, kept while the file is unchanged.
var (
	sdnAutoIDSMu    sync.Mutex
	sdnAutoIDSPath  string
	sdnAutoIDSMod   time.Time
	sdnAutoIDSLists map[string][]netip.Prefix
)

func sdnAutoIDSLoad(path string) (map[string][]netip.Prefix, time.Time) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}
	}
	sdnAutoIDSMu.Lock()
	defer sdnAutoIDSMu.Unlock()
	if path == sdnAutoIDSPath && fi.ModTime().Equal(sdnAutoIDSMod) {
		return sdnAutoIDSLists, sdnAutoIDSMod
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}
	}
	defer f.Close()
	lists := sdn.ParseIDSAutoLists(f)
	sdnAutoIDSPath, sdnAutoIDSMod, sdnAutoIDSLists = path, fi.ModTime(), lists
	return lists, sdnAutoIDSMod
}

// sdnAutoLive returns an auto group's raw networks from its live source.
func sdnAutoLive(repDir, idsRules, id string) ([]netip.Prefix, time.Time, bool) {
	def := sdn.AutoGroupByID(id)
	if def == nil {
		return nil, time.Time{}, false
	}
	if def.Source == "firewall" {
		ps, mod := sdnRepLoad(filepath.Join(repDir, def.RepList+".txt"))
		return ps, mod, len(ps) > 0
	}
	lists, mod := sdnAutoIDSLoad(idsRules)
	ps := lists[id]
	return ps, mod, len(ps) > 0
}

func sdnAutoCacheRead(configDir string) map[string][]string {
	m := map[string][]string{}
	if b, err := os.ReadFile(autoGroupCachePath(configDir)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// SDNAutoGroupCIDRsFunc is the compiler's auto group source: the live list,
// else the boot cache, else an error (the compiler then declares the set
// empty).
func SDNAutoGroupCIDRsFunc(configDir string) func(string) ([]string, error) {
	return func(id string) ([]string, error) {
		repDir, idsRules, _ := sdnAutoPaths(configDir)
		if ps, _, ok := sdnAutoLive(repDir, idsRules, id); ok {
			return sdn.CleanAutoCIDRs(ps), nil
		}
		if v, ok := sdnAutoCacheRead(configDir)[id]; ok && len(v) > 0 {
			return v, nil
		}
		return nil, errors.New("list not available")
	}
}

// SDNAutoGroups describes every auto group for the UI.
func SDNAutoGroups(configDir string) []SDNAutoGroupInfo {
	repDir, idsRules, idsOn := sdnAutoPaths(configDir)
	cache := sdnAutoCacheRead(configDir)
	_, idsErr := os.Stat(idsRules)
	out := make([]SDNAutoGroupInfo, 0, len(sdn.AutoGroupCatalog))
	for _, def := range sdn.AutoGroupCatalog {
		in := SDNAutoGroupInfo{AutoGroupDef: def}
		ps, mod, ok := sdnAutoLive(repDir, idsRules, def.ID)
		if ok {
			clean := sdn.CleanAutoCIDRs(ps)
			in.Available, in.Entries, in.Removed, in.Updated = true, len(clean), len(ps)-len(clean), mod
			in.Present = def.Source == "ids"
		} else if v := cache[def.ID]; len(v) > 0 {
			in.Cached, in.Entries = true, len(v)
		}
		switch {
		case def.Source == "firewall" && !ok:
			in.Note = "Not downloaded yet: it comes with the daily location database update (Traffic & GeoMap)."
		case def.Source == "ids" && !idsOn && idsErr == nil && ok:
			in.Note = "The IDS is off: this is the last list it downloaded, no longer updated."
		case def.Source == "ids" && !ok && idsErr != nil:
			in.Note = "Comes from the IDS rules: turn the IDS on (Intrusion detection) to get it."
		case def.Source == "ids" && !ok:
			in.Note = "Not in the active IDS rules: enable its category or source on the Intrusion detection page."
		}
		if in.Cached && !ok {
			in.Note += " The copy kept for the firewall is still used."
		}
		out = append(out, in)
	}
	return out
}

// SDNAutoGroupEntries returns the cleaned networks of one auto group.
func SDNAutoGroupEntries(configDir, id string) ([]string, error) {
	if sdn.AutoGroupByID(id) == nil {
		return nil, fmt.Errorf("unknown auto group")
	}
	v, err := SDNAutoGroupCIDRsFunc(configDir)(id)
	if err != nil {
		return []string{}, nil
	}
	return v, nil
}

// SDNRefreshAutoGroupCache stores the lists c uses (the boot cache).
func SDNRefreshAutoGroupCache(configDir string, c *sdn.Config, env sdn.Env) {
	if env.AutoGroupCIDRs == nil || c == nil {
		return
	}
	m := map[string][]string{}
	for _, id := range c.UsedAutoGroups() {
		if v, err := env.AutoGroupCIDRs(id); err == nil && len(v) > 0 {
			m[id] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	_ = sdnWriteFile(autoGroupCachePath(configDir), b)
}

// Content last loaded into each live set (by this process).
var (
	sdnAutoSetMu   sync.Mutex
	sdnAutoSetHash = map[string]string{}
)

func hashList(v []string) string {
	h := sha256.Sum256([]byte(strings.Join(v, ",")))
	return hex.EncodeToString(h[:8])
}

// SDNRefreshAutoSets loads fresh list content into the running firewall's
// auto sets — after the daily list download and after an IDS rule update.
// Only changed sets are touched, in one nft transaction (flush + add commit
// together, so there is no moment with an empty set). Nothing happens while
// a change waits for confirmation or in safe mode.
func SDNRefreshAutoSets(configDir string) {
	if configDir == "" {
		return
	}
	st := sdn.Store{Dir: configDir}
	state, err := st.LoadState()
	if err != nil || !state.Enabled {
		return
	}
	if _, pending := SDNPendingRevert(st); pending || SDNSafeModeReason() != "" {
		return
	}
	c, err := st.LoadConfirmed()
	if err != nil || c == nil {
		return
	}
	used := c.UsedAutoGroups()
	if len(used) == 0 {
		return
	}
	get := SDNAutoGroupCIDRsFunc(configDir)
	var script strings.Builder
	next := map[string]string{}
	for _, id := range used {
		v, err := get(id)
		if err != nil {
			continue // keep what the set holds: never empty a list we cannot read now
		}
		h := hashList(v)
		next[id] = h
		sdnAutoSetMu.Lock()
		same := sdnAutoSetHash[id] == h
		sdnAutoSetMu.Unlock()
		if !same {
			script.WriteString(sdn.AutoSetRefreshScript(id, v))
		}
	}
	if script.Len() > 0 {
		if _, err := sdnRun.Run([]byte(script.String()), "nft", "-f", "-"); err != nil {
			// The set may not exist yet (ruleset from an older version):
			// a full refresh declares it.
			log.Printf("[sdn] auto groups: set update failed (%v) — reloading the ruleset", err)
			if err := SDNRefreshRuleset(st, sdnRuntimeEnv); err != nil {
				log.Printf("[sdn] auto groups: %v", err)
				return
			}
		}
	}
	sdnAutoSetMu.Lock()
	for id, h := range next {
		sdnAutoSetHash[id] = h
	}
	sdnAutoSetMu.Unlock()
	SDNRefreshAutoGroupCache(configDir, c, sdn.Env{AutoGroupCIDRs: get})
}

// sdnAutoSetsLoaded records what a full compile just loaded, so the next
// daily refresh only touches lists that really changed.
func sdnAutoSetsLoaded(c *sdn.Config, env sdn.Env) {
	if c == nil || env.AutoGroupCIDRs == nil {
		return
	}
	sdnAutoSetMu.Lock()
	defer sdnAutoSetMu.Unlock()
	for _, id := range c.UsedAutoGroups() {
		if v, err := env.AutoGroupCIDRs(id); err == nil {
			sdnAutoSetHash[id] = hashList(v)
		} else {
			delete(sdnAutoSetHash, id)
		}
	}
}
