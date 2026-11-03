package system

// Intrusion detection (spec §11.4): Suricata in IDS (alert-only) mode, run
// by the Firewall's own unit znas-sdn-ids.service from a configuration
// written here. Rules come from suricata-update (free sets only) into the
// statistics directory (a pool dataset — never the appliance's stick), once
// a day. Alerts reach the portal over a datagram socket: Suricata writes no
// log file at all.

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/ids"
	"zfsnas/internal/sdn"
)

const sdnIDSUnitName = "znas-sdn-ids.service"

var (
	sdnIDSConf      = "/etc/znas-sdn/suricata.yaml"
	sdnIDSThreshold = "/etc/znas-sdn/threshold.config"
	// sdnIDSSocket / sdnIDSState live in the portal's config dir (set at
	// startup by SDNSetConfigDir): the portal owns the alert socket.
	sdnIDSSocket = "/opt/zfsnas/config/sdn/ids-eve.sock"
	sdnIDSState  = "/opt/zfsnas/config/sdn/ids-state.json"
)

// SDNSetIDSPaths points the socket and update state at the config dir.
// SDNSetConfigDir records the portal's config dir: ownership checks, the
// alert socket, the rule-update state and the feature state (sudoers).
func SDNSetConfigDir(configDir string) {
	sdnConfigDir = configDir
	sdnIDSSocket = filepath.Join(configDir, "sdn", "ids-eve.sock")
	sdnIDSState = filepath.Join(configDir, "sdn", "ids-state.json")
}

// SDNEnabledOnDisk reports whether the Firewall feature is enabled.
func SDNEnabledOnDisk() bool {
	st, err := (sdn.Store{Dir: sdnConfigDir}).LoadState()
	return err == nil && st.Enabled
}

func sdnIDSUnitPath() string { return filepath.Join(filepath.Dir(sdnUnitPath), sdnIDSUnitName) }

// sdnIDSUnitText: inert until the Firewall writes a Suricata config.
// Restart=always: a watched PPPoE link may not exist yet when it starts.
func sdnIDSUnitText() string {
	return fmt.Sprintf(`[Unit]
Description=ZNAS Firewall — intrusion detection (Suricata)
After=znas-sdn.service network-online.target zfs-mount.service
ConditionPathExists=%[1]s

[Service]
Type=simple
RuntimeDirectory=znas-sdn-ids
ExecStart=/usr/bin/suricata -c %[1]s --af-packet --pidfile /run/znas-sdn-ids/suricata.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
RestartSec=10
Nice=10

[Install]
WantedBy=multi-user.target
`, sdnIDSConf)
}

// SDNSuricataInstalled reports whether suricata and suricata-update exist.
func SDNSuricataInstalled() bool {
	return (binaryPresent("/usr/bin/suricata") || binaryPresent("suricata")) &&
		(binaryPresent("/usr/bin/suricata-update") || binaryPresent("suricata-update"))
}

// SDNDisableDistroSuricata stops and disables the package's own service and
// rule-update timer (they start on install).
func SDNDisableDistroSuricata() {
	sdnRun.Run(nil, "systemctl", "disable", "--now", "suricata.service")      //nolint:errcheck
	sdnRun.Run(nil, "systemctl", "disable", "--now", "suricata-update.timer") //nolint:errcheck — not shipped everywhere
}

// SDNIDSDir holds the rule sets: the statistics pool dataset, else
// /var/lib on a host and RAM on the appliance.
func SDNIDSDir(statsDir string) string {
	switch {
	case statsDir != "":
		return filepath.Join(statsDir, "suricata")
	case ApplianceMode():
		return "/run/znas-sdn-ids-rules"
	}
	return "/var/lib/znas-sdn/suricata"
}

func sdnIDSPaths(c *sdn.Config) sdn.IDSPaths {
	return sdn.IDSPaths{RulesDir: filepath.Join(SDNIDSDir(c.Settings.StatsDir), "rules"), LogDir: "/run/znas-sdn-ids",
		Socket: sdnIDSSocket, Threshold: sdnIDSThreshold}
}

// sdnIDSFiles writes (or, IDS off, removes) the Suricata config and the
// suppress list. Returns what changed.
func sdnIDSFiles(c *sdn.Config) (confChanged, thrChanged bool, err error) {
	if !c.IDSRuns() {
		for _, p := range []string{sdnIDSConf, sdnIDSThreshold} {
			if _, err := os.Stat(p); err == nil {
				if err := sdnRemoveFile(p); err != nil {
					return confChanged, thrChanged, err
				}
				confChanged = true
			}
		}
		return confChanged, false, nil
	}
	write := func(p, text string) (bool, error) {
		if cur, err := os.ReadFile(p); err == nil && string(cur) == text {
			return false, nil
		}
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			sdnRun.Run(nil, "mkdir", "-p", filepath.Dir(p)) //nolint:errcheck
		}
		return true, sdnWriteFile(p, []byte(text))
	}
	if thrChanged, err = write(sdnIDSThreshold, sdn.RenderThreshold(c)); err != nil {
		return
	}
	confChanged, err = write(sdnIDSConf, sdn.RenderSuricataYAML(c, sdnIDSPaths(c)))
	return
}

// sdnApplyIDS (after the ruleset): restart on a new configuration, reload
// rules for a new suppress list, stop when turned off.
func sdnApplyIDS(c *sdn.Config, confChanged, thrChanged bool, res *SDNApplyResult) {
	if !c.IDSRuns() {
		if confChanged {
			sdnRun.Run(nil, "systemctl", "stop", sdnIDSUnitName) //nolint:errcheck
		}
		return
	}
	active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnIDSUnitName)
	switch {
	case confChanged || strings.TrimSpace(string(active)) != "active":
		if _, err := sdnRun.Run(nil, "systemctl", "restart", sdnIDSUnitName); err != nil {
			res.Warnings = append(res.Warnings, "intrusion detection did not start: "+err.Error())
		}
	case thrChanged:
		sdnRun.Run(nil, "systemctl", "reload", sdnIDSUnitName) //nolint:errcheck
	}
}

// ── rule updates ─────────────────────────────────────────────────────────

// SDNIDSState is the result of the last rule update.
type SDNIDSState struct {
	UpdatedAt    time.Time `json:"updated_at"`
	Groups       []string  `json:"groups"`        // ET Open groups available
	RulesEnabled int       `json:"rules_enabled"` // after the category filter
	Key          string    `json:"key"`           // sources + categories it was made for
	Error        string    `json:"error,omitempty"`
	Running      bool      `json:"running"`
}

var (
	sdnIDSUpdateMu sync.Mutex
	sdnIDSUpdating bool
	sdnIDSStateMu  sync.Mutex
)

// SDNIDSReadState returns the last update result.
func SDNIDSReadState() SDNIDSState {
	sdnIDSStateMu.Lock()
	defer sdnIDSStateMu.Unlock()
	var s SDNIDSState
	if b, err := os.ReadFile(sdnIDSState); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.Groups == nil {
		s.Groups = []string{}
	}
	s.Running = sdnIDSUpdating
	return s
}

func sdnIDSWriteState(s SDNIDSState) {
	sdnIDSStateMu.Lock()
	defer sdnIDSStateMu.Unlock()
	if b, err := json.MarshalIndent(s, "", "  "); err == nil {
		_ = os.WriteFile(sdnIDSState, b, 0644)
	}
}

func idsKey(c *sdn.Config) string {
	src := append([]string{}, c.IDS.Sources...)
	cat := append([]string{}, c.IDS.Categories...)
	sort.Strings(src)
	sort.Strings(cat)
	return strings.Join(src, ",") + "|" + strings.Join(cat, ",")
}

// SDNIDSNeedsUpdate: rules missing, made for other choices, or a day old.
func SDNIDSNeedsUpdate(c *sdn.Config) bool {
	if !c.IDS.Enabled {
		return false
	}
	s := SDNIDSReadState()
	if s.Key != idsKey(c) || time.Since(s.UpdatedAt) > 24*time.Hour {
		return true
	}
	_, err := os.Stat(filepath.Join(sdnIDSPaths(c).RulesDir, "suricata.rules"))
	return err != nil
}

var sdnWrittenRe = regexp.MustCompile(`enabled: (\d+)`)

// sdnETGroups lists the rule files of the cached ET Open tarball.
var sdnETGroups = func(dataDir string) []string {
	matches, _ := filepath.Glob(filepath.Join(dataDir, "update", "cache", "*emerging.rules.tar.gz"))
	var out []string
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			continue
		}
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			name := strings.TrimSuffix(filepath.Base(h.Name), ".rules")
			// Only plain group names reach disable.conf (a downloaded
			// archive's names are not trusted).
			if strings.HasSuffix(h.Name, ".rules") && !strings.HasSuffix(name, "deleted") && sdn.IDSGroupNameOK(name) {
				out = append(out, name)
			}
		}
		f.Close()
	}
	sort.Strings(out)
	return out
}

// SDNIDSUpdate downloads the rule sets and builds the rule file: ET Open
// (always) plus the chosen free sources, with only the chosen ET groups.
// The first run downloads twice (the group list comes from the download).
// A running engine reloads its rules.
func SDNIDSUpdate(c *sdn.Config) error {
	sdnIDSUpdateMu.Lock()
	defer sdnIDSUpdateMu.Unlock()
	sdnIDSStateMu.Lock()
	sdnIDSUpdating = true
	sdnIDSStateMu.Unlock()
	defer func() { sdnIDSStateMu.Lock(); sdnIDSUpdating = false; sdnIDSStateMu.Unlock() }()

	st := SDNIDSReadState()
	err := sdnIDSUpdate(c, &st)
	st.Error = ""
	if err != nil {
		st.Error = err.Error()
		log.Printf("[sdn] IDS rule update: %v", err)
	}
	sdnIDSWriteState(st)
	return err
}

func sdnIDSUpdate(c *sdn.Config, st *SDNIDSState) error {
	base := SDNIDSDir(c.Settings.StatsDir)
	data, rules := filepath.Join(base, "data"), filepath.Join(base, "rules")
	if os.MkdirAll(data, 0755) != nil || os.MkdirAll(rules, 0755) != nil {
		if _, err := sdnRun.Run(nil, "mkdir", "-p", data, rules); err != nil {
			return err
		}
	}
	su := func(args ...string) ([]byte, error) {
		return sdnRun.Run(nil, "suricata-update", append([]string{"-D", data}, args...)...)
	}
	if _, err := su("update-sources"); err != nil {
		return fmt.Errorf("cannot fetch the rule set index: %w", err)
	}
	enabled := map[string]bool{}
	if out, err := su("list-enabled-sources"); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if n, ok := strings.CutPrefix(strings.TrimSpace(l), "- "); ok {
				enabled[strings.TrimSpace(n)] = true
			}
		}
	}
	want := map[string]bool{"et/open": true}
	for _, s := range c.IDS.Sources {
		want[s] = true
	}
	for n := range want {
		if !enabled[n] {
			if _, err := su("enable-source", n); err != nil {
				return fmt.Errorf("rule set %s: %w", n, err)
			}
		}
	}
	for n := range enabled {
		if !want[n] {
			su("disable-source", n) //nolint:errcheck
		}
	}
	disable := filepath.Join(data, "disable.conf")
	run := func(offline bool) error {
		if err := sdnWriteFile(disable, []byte(sdn.RenderDisableConf(c, sdnETGroups(data)))); err != nil {
			return err
		}
		args := []string{"-o", rules, "--no-test", "--no-reload", "--disable-conf", disable}
		if offline {
			args = append(args, "--offline")
		}
		out, err := su(args...)
		if err != nil {
			return fmt.Errorf("rule download failed: %w", err)
		}
		if m := sdnWrittenRe.FindAllSubmatch(out, -1); len(m) > 0 {
			st.RulesEnabled, _ = strconv.Atoi(string(m[len(m)-1][1]))
		}
		return nil
	}
	firstRun := len(sdnETGroups(data)) == 0
	if err := run(false); err != nil {
		return err
	}
	if firstRun {
		// Now that the group list is known, filter the categories.
		if err := run(true); err != nil {
			return err
		}
	}
	st.Groups = sdnETGroups(data)
	st.UpdatedAt = time.Now().UTC()
	st.Key = idsKey(c)
	if active, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnIDSUnitName); strings.TrimSpace(string(active)) == "active" {
		sdnRun.Run(nil, "systemctl", "reload", sdnIDSUnitName) //nolint:errcheck
	}
	return nil
}

// StartSDNIDSUpdater checks every 30 min whether the rules need an update
// (first enable, changed choices, a day old). load returns the running
// configuration (nil when the Firewall is off).
func StartSDNIDSUpdater(load func() *sdn.Config) {
	go func() {
		time.Sleep(2 * time.Minute)
		for {
			if c := load(); c != nil && SDNIDSNeedsUpdate(c) && SDNSuricataInstalled() {
				_ = SDNIDSUpdate(c)
			}
			time.Sleep(30 * time.Minute)
		}
	}()
}

// ── alerts from Suricata ─────────────────────────────────────────────────

var (
	sdnIDSStore     *ids.Store
	sdnIDSStoreOnce sync.Once
	// SDNIDSOnAlert is called for every alert (ZNAS alert notifications).
	SDNIDSOnAlert func(ids.Event)
)

// SDNIDSStore is the alert store (memory, saved under the stats dir).
func SDNIDSStore() *ids.Store {
	sdnIDSStoreOnce.Do(func() { sdnIDSStore = ids.NewStore("") })
	return sdnIDSStore
}

// sdnIDSStorePath: where alerts are kept ("" = RAM only, no pool chosen).
func sdnIDSStorePath(statsDir string) string {
	if statsDir == "" {
		return ""
	}
	return filepath.Join(statsDir, "ids-alerts.json.gz")
}

// StartSDNIDSIngest listens on the alert socket and saves the store every
// 10 minutes. statsDir returns the current statistics directory.
func StartSDNIDSIngest(statsDir func() string) {
	sdnIDSStoreOnce.Do(func() { sdnIDSStore = ids.NewStore(sdnIDSStorePath(statsDir())) })
	go func() {
		for {
			if err := sdnIDSListen(); err != nil {
				log.Printf("[sdn] IDS alert socket: %v", err)
			}
			time.Sleep(30 * time.Second)
		}
	}()
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			s := SDNIDSStore()
			if p := sdnIDSStorePath(statsDir()); p != s.Path() {
				// Statistics moved (pool chosen): carry the alerts over.
				s.MoveTo(p)
			}
			if err := s.Save(); err != nil {
				log.Printf("[sdn] IDS alerts save: %v", err)
			}
		}
	}()
}

func sdnIDSListen() error {
	_ = os.Remove(sdnIDSSocket)
	if err := os.MkdirAll(filepath.Dir(sdnIDSSocket), 0755); err != nil {
		return err
	}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sdnIDSSocket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, 256*1024)
	for {
		n, _, err := conn.ReadFromUnix(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return err
			}
			return err
		}
		if e, ok := ids.ParseEVE(buf[:n]); ok {
			sdnIDSNATResolver.resolve(&e, time.Now())
			SDNIDSStore().Add(e)
			if SDNIDSOnAlert != nil {
				SDNIDSOnAlert(e)
			}
		}
	}
}

// SDNIDSFlush saves the alerts (portal shutdown).
func SDNIDSFlush() {
	if sdnIDSStore != nil {
		if err := sdnIDSStore.Save(); err != nil {
			log.Printf("[sdn] IDS alerts save: %v", err)
		}
	}
}

// SDNIDSRunning reports whether the engine runs.
func SDNIDSRunning() bool {
	out, _ := sdnRun.Run(nil, "systemctl", "is-active", sdnIDSUnitName)
	return strings.TrimSpace(string(out)) == "active"
}
