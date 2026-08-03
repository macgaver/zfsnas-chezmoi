package system

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
)

// sysfsRead reads a trimmed string from a sysfs file, returning "" on error.
func sysfsRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SysBatteryPath returns the sysfs path of the first Battery-type power supply,
// or "" if none is found.
func SysBatteryPath() string {
	entries, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		dir := "/sys/class/power_supply/" + e.Name()
		if sysfsRead(dir+"/type") == "Battery" {
			return dir
		}
	}
	return ""
}

// QuerySysBattery reads battery data from /sys/class/power_supply and returns
// a UPSStatus populated with the available fields. Returns nil when no battery
// is present.
func QuerySysBattery() *UPSStatus {
	dir := SysBatteryPath()
	if dir == "" {
		return nil
	}

	s := &UPSStatus{
		Name:         sysfsRead(dir + "/model_name"),
		Manufacturer: sysfsRead(dir + "/manufacturer"),
		Model:        sysfsRead(dir + "/model_name"),
		Serial:       sysfsRead(dir + "/serial_number"),
		AllVars:      map[string]string{},
	}

	status := sysfsRead(dir + "/status") // "Charging", "Discharging", "Not charging", "Full"
	acDir := ""
	if acentries, err := os.ReadDir("/sys/class/power_supply"); err == nil {
		for _, e := range acentries {
			if sysfsRead("/sys/class/power_supply/"+e.Name()+"/type") == "Mains" {
				acDir = "/sys/class/power_supply/" + e.Name()
				break
			}
		}
	}
	acOnline := acDir != "" && sysfsRead(acDir+"/online") == "1"

	s.OnLine = acOnline
	s.OnBattery = !acOnline && status == "Discharging"
	switch status {
	case "Charging":
		s.RawStatus = "OL CHRG"
	case "Discharging":
		s.RawStatus = "OB"
	case "Full":
		s.RawStatus = "OL"
	default:
		if acOnline {
			s.RawStatus = "OL"
		} else {
			s.RawStatus = "OB"
		}
	}

	if cap := sysfsRead(dir + "/capacity"); cap != "" {
		if f, err := strconv.ParseFloat(cap, 64); err == nil {
			s.ChargePct = &f
			s.LowBattery = f <= 10
		}
	}

	// voltage_now is in µV
	if v := sysfsRead(dir + "/voltage_now"); v != "" {
		if uv, err := strconv.ParseFloat(v, 64); err == nil {
			volts := uv / 1_000_000
			s.BattVoltage = &volts
		}
	}

	// Estimate runtime from charge_now / current_now (both in µAh/µA)
	if s.OnBattery {
		chargeNow := sysfsRead(dir + "/charge_now")
		currentNow := sysfsRead(dir + "/current_now")
		if chargeNow != "" && currentNow != "" {
			cn, err1 := strconv.ParseFloat(chargeNow, 64)
			cur, err2 := strconv.ParseFloat(currentNow, 64)
			if err1 == nil && err2 == nil && cur > 0 {
				runtimeSecs := int((cn / cur) * 3600)
				s.RuntimeSecs = &runtimeSecs
			}
		}
	}

	// Temperature: in tenths of °C
	if t := sysfsRead(dir + "/temp"); t != "" {
		if tv, err := strconv.ParseFloat(t, 64); err == nil {
			c := tv / 10
			s.TempC = &c
		}
	}

	// Populate AllVars for the detail panel
	for _, field := range []string{"capacity", "status", "health", "technology", "cycle_count", "capacity_level"} {
		if v := sysfsRead(dir + "/" + field); v != "" {
			s.AllVars[field] = v
		}
	}
	if s.Serial != "" {
		s.AllVars["ups.serial"] = s.Serial
	}

	return s
}

// UPSPrereqsInstalled returns true when the nut packages are present.
func UPSPrereqsInstalled() bool {
	return binaryInstalled("upsc", "upsd")
}

// UPSStatus describes the current state of the UPS.
type UPSStatus struct {
	Name          string            `json:"name"`
	RawStatus     string            `json:"raw_status"`
	OnLine        bool              `json:"on_line"`
	OnBattery     bool              `json:"on_battery"`
	LowBattery    bool              `json:"low_battery"`
	ChargePct     *float64          `json:"charge_pct"`
	RuntimeSecs   *int              `json:"runtime_secs"`
	BattVoltage   *float64          `json:"batt_voltage"`
	InputVoltage  *float64          `json:"input_voltage"`
	OutputVoltage *float64          `json:"output_voltage"`
	LoadPct       *float64          `json:"load_pct"`
	TempC         *float64          `json:"temp_c"`
	Model         string            `json:"model"`
	Manufacturer  string            `json:"manufacturer"`
	Serial        string            `json:"serial"`
	AllVars       map[string]string `json:"all_vars"`
}

// QueryUPS runs `upsc <name>@localhost` and parses the output into UPSStatus.
func QueryUPS(name string) (*UPSStatus, error) {
	return QueryUPSAt(name + "@localhost")
}

// RunUPSCalibration starts a battery runtime-calibration test on the local UPS
// via the NUT `calibrate.start` instant command. It authenticates as the local
// "upsmon" user (which ZNAS grants instcmds=ALL in /etc/nut/upsd.users), so no
// sudo is needed — upscmd talks to upsd over the NUT protocol on localhost.
//
// Calibration is optional (most UPSes self-calibrate periodically) and not all
// models support it; when unsupported, upscmd returns a clear NUT error which is
// surfaced to the caller unchanged.
func RunUPSCalibration(name, monitorPassword string) error {
	if name == "" {
		return fmt.Errorf("no local UPS configured")
	}
	out, err := exec.Command("upscmd", "-u", "upsmon", "-p", monitorPassword,
		name+"@localhost", "calibrate.start").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// QueryUPSAt runs `upsc <target>` where target is "name@host" or "name@host:port".
func QueryUPSAt(target string) (*UPSStatus, error) {
	out, err := exec.Command("upsc", target).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("upsc failed: %w — %s", err, strings.TrimSpace(string(out)))
	}

	vars := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, ": "); idx >= 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+2:])
			vars[k] = v
		}
	}

	// Use the device name part of the target (before the first '@').
	devName := target
	if idx := strings.Index(target, "@"); idx >= 0 {
		devName = target[:idx]
	}
	s := &UPSStatus{Name: devName, AllVars: vars}

	if v, ok := vars["ups.status"]; ok {
		s.RawStatus = v
		s.OnLine = strings.Contains(v, "OL")
		s.OnBattery = strings.Contains(v, "OB")
		s.LowBattery = strings.Contains(v, "LB")
	}
	if v, ok := vars["battery.charge"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.ChargePct = &f
		}
	}
	if v, ok := vars["battery.runtime"]; ok {
		if i, err := strconv.Atoi(v); err == nil {
			s.RuntimeSecs = &i
		}
	}
	if v, ok := vars["battery.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.BattVoltage = &f
		}
	}
	if v, ok := vars["input.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.InputVoltage = &f
		}
	}
	if v, ok := vars["output.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.OutputVoltage = &f
		}
	}
	if v, ok := vars["ups.load"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.LoadPct = &f
		}
	}
	if v, ok := vars["ups.temperature"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.TempC = &f
		}
	}
	s.Model = vars["ups.model"]
	s.Manufacturer = vars["ups.mfr"]
	s.Serial = vars["ups.serial"]

	return s, nil
}

// DetectedUPS holds the result of auto-detection.
type DetectedUPS struct {
	Name            string `json:"name"`
	Driver          string `json:"driver"`
	Port            string `json:"port"`
	MonitorPassword string `json:"monitor_password"`
	ScannerOutput   string `json:"scanner_output,omitempty"` // raw nut-scanner output for debugging
}

// generateMonitorPassword returns a random 32-character hex string.
func generateMonitorPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// fallback: use time-based value
		return fmt.Sprintf("%x%x", time.Now().UnixNano(), time.Now().UnixNano()^0xdeadbeef)
	}
	return hex.EncodeToString(b)
}

// DetectAndConfigureUPS writes all NUT daemon infrastructure config files
// (nut.conf, upsd.conf, upsd.users) regardless of whether a UPS is detected,
// then runs nut-scanner to find a device. If found, ups.conf and upsmon.conf
// are written and nut-client is started. nut-server is always started.
//
// existingPassword is reused when provided (e.g. on re-scan); pass "" to
// generate a new one on first install.
//
// Always returns a non-nil *DetectedUPS with MonitorPassword set.
// Name/Driver/Port are empty when no device was found.
func DetectAndConfigureUPS(existingPassword string) (*DetectedUPS, error) {
	password := existingPassword
	if password == "" {
		password = generateMonitorPassword()
	}

	// Always write daemon infrastructure in standalone mode — auto-detection
	// never runs in netserver/netclient context.
	if err := ConfigureNUTDaemon("standalone", "127.0.0.1", 3493, password); err != nil {
		return &DetectedUPS{MonitorPassword: password}, fmt.Errorf("write NUT daemon config: %w", err)
	}

	// Locate nut-scanner — it may live in /usr/sbin which is not always in sudo PATH.
	scannerBin := "/usr/sbin/nut-scanner"
	if _, err := os.Stat(scannerBin); err != nil {
		if p, err2 := exec.LookPath("nut-scanner"); err2 == nil {
			scannerBin = p
		}
	}

	// -C outputs NUT config-file format (ready for ups.conf).
	// -N skips network protocol scanning (USB UPS scan is instant).
	// Use Output() (stdout only) — nut-scanner writes noise to stderr that must
	// not end up in ups.conf (missing SNMP/XML/IPMI libs, avahi errors, etc.).
	scanOut, _ := nutScannerOutput(scannerBin, "-C", "-N")
	scanRaw := strings.TrimSpace(scanOut)

	// Fallback: try full scan if -C -N produced nothing.
	if !strings.Contains(scanRaw, "[") {
		scanOut2, _ := nutScannerOutput(scannerBin, "-a", "-t", "2")
		if s := strings.TrimSpace(scanOut2); strings.Contains(s, "[") {
			scanRaw = s
		}
	}

	result := &DetectedUPS{MonitorPassword: password, ScannerOutput: scanRaw}

	if strings.Contains(scanRaw, "[") {
		// Write the scanner output to ups.conf, stripping hardware-specific
		// location keys that break NUT when the UPS moves USB ports.
		filtered := filterUPSConfLines(scanRaw)
		if err := writeFileViaSudo("/etc/nut/ups.conf", filtered+"\n", 0640); err != nil {
			return result, fmt.Errorf("write ups.conf: %w", err)
		}

		// Parse device name from first section header, e.g. [nutdev1].
		result.Name = parseSectionName(scanRaw)
		// Also parse driver/port for display in the UI.
		if d := parseNutScannerOutput(scanRaw); d != nil {
			result.Driver = d.Driver
			result.Port = d.Port
			if result.Name == "" {
				result.Name = d.Name
			}
		}

		if result.Name != "" {
			if err := ApplyUPSMonConfig(result.Name, password); err != nil {
				return result, fmt.Errorf("write upsmon.conf: %w", err)
			}
		}
	}

	fixNUTPermissions()

	// Write a udev rule so the nut user can access the USB device before
	// nut-server starts. This must happen before the service is enabled.
	if vid, pid := parseUPSUSBIDs(scanRaw); vid != "" && pid != "" {
		if err := writeNUTUdevRule(vid, pid); err != nil {
			log.Printf("[ups] udev rule write failed (non-fatal): %v", err)
		}
	}

	// nut-server can start without any devices defined.
	exec.Command("sudo", "systemctl", "enable", "nut-server").Run()
	exec.Command("sudo", "systemctl", "restart", "nut-server").Run()

	// nut-client (upsmon) requires a valid upsmon.conf with a known device.
	if result.Name != "" {
		exec.Command("sudo", "systemctl", "enable", "nut-client").Run()
		exec.Command("sudo", "systemctl", "restart", "nut-client").Run()
	}

	// Brief pause so upsd has time to bind the socket before upsc queries it.
	time.Sleep(2 * time.Second)

	return result, nil
}

// parseSectionName returns the name inside the first [section] header in raw.
func parseSectionName(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			return strings.TrimSpace(line[1 : len(line)-1])
		}
	}
	return ""
}

// filterUPSConfLines removes hardware-location keys (bus, device, busport)
// from nut-scanner output before writing ups.conf. Those keys are USB-port-
// specific and cause NUT to fail to connect if the UPS is plugged into a
// different port after the config was generated.
func filterUPSConfLines(raw string) string {
	skip := map[string]bool{"bus": true, "device": true, "busport": true}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		key := strings.ToLower(strings.TrimSpace(strings.SplitN(line, "=", 2)[0]))
		key = strings.Trim(key, `"`)
		if skip[key] {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// parseNutScannerOutput parses INI-style nut-scanner output and returns the
// first device's driver and port. The Name field is left empty; use
// parseSectionName to get the actual device name from the section header.
func parseNutScannerOutput(raw string) *DetectedUPS {
	var current *DetectedUPS
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = &DetectedUPS{}
			continue
		}
		if current == nil {
			continue
		}
		k, v, ok := parseIniKV(line)
		if !ok {
			continue
		}
		switch k {
		case "driver":
			current.Driver = v
		case "port":
			current.Port = v
		}
		if current.Driver != "" && current.Port != "" {
			return current
		}
	}
	return nil
}

// parseIniKV splits "key = value" (with optional quotes on value).
func parseIniKV(line string) (k, v string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return
	}
	k = strings.TrimSpace(line[:idx])
	v = strings.TrimSpace(line[idx+1:])
	v = strings.Trim(v, `"'`)
	ok = k != ""
	return
}


// ConfigureNUTDaemon writes the NUT daemon infrastructure files:
// nut.conf (MODE=<mode>), upsd.conf (LISTEN <listenIP> <listenPort>),
// and upsd.users (full-access monitor user with the given password).
// ups.conf is written separately once a device is detected.
// mode must be "standalone", "netserver", or "netclient".
// For "netclient", upsd.conf and upsd.users are not written (no local server).
func ConfigureNUTDaemon(mode, listenIP string, listenPort int, monitorPassword string) error {
	if mode == "" {
		mode = "standalone"
	}
	if listenIP == "" {
		listenIP = "127.0.0.1"
	}
	if listenPort <= 0 {
		listenPort = 3493
	}

	if err := writeFileViaSudo("/etc/nut/nut.conf", "MODE="+mode+"\n", 0640); err != nil {
		return fmt.Errorf("write nut.conf: %w", err)
	}

	// netclient has no local upsd — skip upsd.conf and upsd.users.
	if mode == "netclient" {
		return nil
	}

	upsdConf := fmt.Sprintf("LISTEN %s %d\n", listenIP, listenPort)
	if err := writeFileViaSudo("/etc/nut/upsd.conf", upsdConf, 0640); err != nil {
		return fmt.Errorf("write upsd.conf: %w", err)
	}

	// Full-access monitor user with generated password.
	upsdUsers := fmt.Sprintf("[upsmon]\n  password  = %s\n  actions   = SET\n  instcmds  = ALL\n  upsmon master\n", monitorPassword)
	if err := writeFileViaSudo("/etc/nut/upsd.users", upsdUsers, 0640); err != nil {
		return fmt.Errorf("write upsd.users: %w", err)
	}

	return nil
}

// ApplyNUTConf writes /etc/nut/nut.conf with the correct MODE directive.
// mode must be "standalone", "netserver", or "netclient".
func ApplyNUTConf(mode string) error {
	content := fmt.Sprintf("# Generated by ZNAS — do not edit manually\nMODE=%s\n", mode)
	return writeFileViaSudo("/etc/nut/nut.conf", content, 0640)
}

// ApplyNUTUpsdConf writes /etc/nut/upsd.conf for network server mode.
func ApplyNUTUpsdConf(srv *config.NUTServerConfig) error {
	ip := srv.ListenIP
	if ip == "" {
		ip = "0.0.0.0"
	}
	port := srv.ListenPort
	if port == 0 {
		port = 3493
	}
	var sb strings.Builder
	sb.WriteString("# Generated by ZNAS — do not edit manually\n")
	sb.WriteString(fmt.Sprintf("LISTEN %s %d\n", ip, port))
	for _, cidr := range srv.AllowedClients {
		sb.WriteString(fmt.Sprintf("ACL myhost %s\n", cidr))
		sb.WriteString("ACCEPT myhost\n")
		sb.WriteString("REJECT ALL\n")
	}
	return writeFileViaSudo("/etc/nut/upsd.conf", sb.String(), 0640)
}

// ApplyNUTUpsdUsers writes /etc/nut/upsd.users for network server mode.
// Always includes the local upsmon master user; adds remote users from config.
func ApplyNUTUpsdUsers(monitorPassword string, remoteUsers []config.NUTRemoteUser) error {
	var sb strings.Builder
	sb.WriteString("# Generated by ZNAS — do not edit manually\n\n")
	sb.WriteString("[upsmon]\n")
	sb.WriteString(fmt.Sprintf("  password = %s\n", monitorPassword))
	sb.WriteString("  actions = SET\n")
	sb.WriteString("  instcmds = ALL\n")
	sb.WriteString("  upsmon master\n\n")
	for _, u := range remoteUsers {
		sb.WriteString(fmt.Sprintf("[%s]\n", u.Username))
		sb.WriteString(fmt.Sprintf("  password = %s\n", u.Password))
		if u.Role == "admin" {
			sb.WriteString("  actions = SET\n")
			sb.WriteString("  instcmds = ALL\n")
		}
		sb.WriteString("  upsmon slave\n\n")
	}
	return writeFileViaSudo("/etc/nut/upsd.users", sb.String(), 0640)
}

// ApplyUPSMonConfigClient writes /etc/nut/upsmon.conf for network client mode.
// Uses "slave" since the remote server owns the UPS.
func ApplyUPSMonConfigClient(client *config.NUTClientConfig) error {
	port := client.Port
	if port == 0 {
		port = 3493
	}
	username := client.Username
	if username == "" {
		username = "upsmon"
	}
	monConf := fmt.Sprintf(`# Generated by ZNAS — do not edit manually
MONITOR %s@%s:%d 1 %s %s slave
SHUTDOWNCMD "/bin/true"
MINSUPPLIES 1
POLLFREQ 5
POLLFREQALERT 5
HOSTSYNC 15
DEADTIME 15
POWERDOWNFLAG /etc/killpower
NOTIFYFLAG ONLINE  SYSLOG+WALL
NOTIFYFLAG ONBATT  SYSLOG+WALL
NOTIFYFLAG LOWBATT SYSLOG+WALL
`, client.UPSName, client.Host, port, username, client.Password)
	return writeFileViaSudo("/etc/nut/upsmon.conf", monConf, 0640)
}

// QueryUPSClient queries a remote NUT server using upsc remote syntax.
func QueryUPSClient(cfg *config.NUTClientConfig) (*UPSStatus, error) {
	port := cfg.Port
	if port == 0 {
		port = 3493
	}
	target := fmt.Sprintf("%s@%s:%d", cfg.UPSName, cfg.Host, port)
	out, err := exec.Command("upsc", target).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("upsc %s: %w — %s", target, err, string(out))
	}
	return parseUPSCOutput(string(out)), nil
}

// parseUPSCOutput parses upsc output into a UPSStatus struct.
func parseUPSCOutput(raw string) *UPSStatus {
	vars := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		if idx := strings.Index(line, ": "); idx >= 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+2:])
			vars[k] = v
		}
	}
	s := &UPSStatus{AllVars: vars}
	if v, ok := vars["ups.status"]; ok {
		s.RawStatus = v
		s.OnLine = strings.Contains(v, "OL")
		s.OnBattery = strings.Contains(v, "OB")
		s.LowBattery = strings.Contains(v, "LB")
	}
	if v, ok := vars["battery.charge"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.ChargePct = &f
		}
	}
	if v, ok := vars["battery.runtime"]; ok {
		if i, err := strconv.Atoi(v); err == nil {
			s.RuntimeSecs = &i
		}
	}
	if v, ok := vars["battery.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.BattVoltage = &f
		}
	}
	if v, ok := vars["input.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.InputVoltage = &f
		}
	}
	if v, ok := vars["output.voltage"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.OutputVoltage = &f
		}
	}
	if v, ok := vars["ups.load"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.LoadPct = &f
		}
	}
	if v, ok := vars["ups.temperature"]; ok {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			s.TempC = &f
		}
	}
	s.Model = vars["ups.model"]
	s.Manufacturer = vars["ups.mfr"]
	s.Serial = vars["ups.serial"]
	return s
}

// ApplyUPSMonConfig writes /etc/nut/upsmon.conf for standalone/netserver mode.
// SHUTDOWNCMD is always a no-op — shutdown is managed by StartUPSShutdownWatcher,
// not by NUT, to allow precise control over timing and thresholds.
func ApplyUPSMonConfig(name, monitorPassword string) error {
	monConf := fmt.Sprintf(`# Generated by ZFSNAS — do not edit manually
MONITOR %s@localhost 1 upsmon %s master
SHUTDOWNCMD "/bin/true"
MINSUPPLIES 1
POLLFREQ 5
POLLFREQALERT 5
HOSTSYNC 15
DEADTIME 15
POWERDOWNFLAG /etc/killpower
NOTIFYFLAG ONLINE  SYSLOG+WALL
NOTIFYFLAG ONBATT  SYSLOG+WALL
NOTIFYFLAG LOWBATT SYSLOG+WALL
`, name, monitorPassword)
	if err := writeFileViaSudo("/etc/nut/upsmon.conf", monConf, 0640); err != nil {
		return fmt.Errorf("write upsmon.conf: %w", err)
	}
	return nil
}


// OnUPSShutdown is an optional callback invoked immediately BEFORE a
// threshold-triggered shutdown. main.go wires it to alerts.SendSync — the dep
// is kept indirect because internal/alerts already imports this package via the
// interlink relay subscription (same reason as OnVMUnexpectedStop).
//
// It must BLOCK until the notification has actually been delivered: the caller
// halts the machine on return, so anything still in flight dies. Implementations
// are responsible for their own timeout — upsNotifyBudget below is the absolute
// cap the watcher enforces regardless.
//
// Arguments: UPS name, a one-line summary, and the same details string the
// audit entry carries. Returns nil when at least one target got the message.
var OnUPSShutdown func(upsName, summary, details string) error

// The shutdown notice gets a hard time budget. The machine is running on a
// battery that just hit the user's threshold, so waiting on a dead network is
// strictly worse than shutting down un-announced: one retry, then go. Worst
// case is attempt + pause + attempt = 14s, inside the 15s budget.
//
// Vars, not consts, so the tests can exercise the timing guarantee without
// actually sitting there for 15 seconds.
var (
	upsNotifyBudget      = 15 * time.Second
	upsNotifyAttempt     = 6 * time.Second
	upsNotifyRetryIn     = 2 * time.Second
	upsNotifyMaxAttempts = 2
)

// notifyUPSShutdown delivers the pre-shutdown notification, retrying once if the
// first attempt fails. Returns as soon as it is delivered, or when the attempts
// or the budget are spent — never later, and never with a panic escaping into
// the shutdown path.
func notifyUPSShutdown(upsName, summary, details string) {
	send := OnUPSShutdown
	if send == nil {
		return
	}
	deadline := time.Now().Add(upsNotifyBudget)
	for attempt := 1; ; attempt++ {
		errc := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errc <- fmt.Errorf("panic: %v", r)
				}
			}()
			errc <- send(upsName, summary, details)
		}()

		select {
		case err := <-errc:
			if err == nil {
				log.Printf("UPS: shutdown notification delivered (attempt %d)", attempt)
				return
			}
			log.Printf("UPS: shutdown notification attempt %d failed: %v", attempt, err)
		case <-time.After(upsNotifyAttempt):
			log.Printf("UPS: shutdown notification attempt %d timed out", attempt)
		}
		if attempt >= upsNotifyMaxAttempts || time.Now().Add(upsNotifyRetryIn).After(deadline) {
			log.Printf("UPS: giving up on the shutdown notification after %d attempt(s) — proceeding with shutdown", attempt)
			return
		}
		time.Sleep(upsNotifyRetryIn)
	}
}

// StartUPSShutdownWatcher polls the UPS every 5 seconds and issues a system
// shutdown when ALL of the following conditions are true:
//  1. UPS feature is enabled and a shutdown policy is configured.
//  2. The UPS reports OnBattery=true and OnLine=false (not on AC power).
//  3. The battery-power condition has been confirmed for ≥20 consecutive seconds.
//  4. The configured threshold (charge %, runtime, or both) has been crossed.
//
// NUT's own SHUTDOWNCMD is always "/bin/true" — this goroutine is the sole
// shutdown authority so that threshold logic stays fully in our control.
func StartUPSShutdownWatcher(appCfg *config.AppConfig) {
	const pollInterval = 5 * time.Second
	const onBatteryRequired = 20 * time.Second

	var onBatterySince time.Time
	shutdownFired := false

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		ups := appCfg.UPS
		if !ups.Enabled || !ups.ShutdownPolicy.Enabled {
			onBatterySince = time.Time{}
			shutdownFired = false
			continue
		}

		mode := ups.Mode
		if mode == "" {
			mode = "standalone"
		}

		var status *UPSStatus
		var err error
		if !UPSPrereqsInstalled() {
			// NUT not installed — use sysfs battery directly.
			status = QuerySysBattery()
			if status == nil {
				continue
			}
		} else {
			switch mode {
			case "network_client":
				if ups.NUTClient != nil && ups.NUTClient.Host != "" {
					status, err = QueryUPSClient(ups.NUTClient)
				} else {
					continue
				}
			default: // standalone or network_server both query localhost
				if ups.UPSName == "" {
					continue
				}
				status, err = QueryUPS(ups.UPSName)
			}
			if err != nil {
				// Transient query failure — keep existing battery timer.
				continue
			}
		}

		// Reset when AC power is restored.
		if !status.OnBattery || status.OnLine {
			onBatterySince = time.Time{}
			shutdownFired = false
			continue
		}

		// First poll on battery — record start time and log the transition.
		if onBatterySince.IsZero() {
			onBatterySince = time.Now()
			audit.Log(audit.Entry{
				User:   "system",
				Role:   "system",
				Action: audit.ActionUPSOnBattery,
				Result: audit.ResultOK,
				Target: ups.UPSName,
				Details: fmt.Sprintf("UPS switched to battery power — AC lost; shutdown policy active: %v", ups.ShutdownPolicy.Enabled),
			})
			deviceName := ups.UPSName
			if deviceName == "" {
				deviceName = "sysfs-battery"
			}
			log.Printf("UPS: AC power lost on %s — now on battery", deviceName)
		}

		// Require 20 s of confirmed battery power before any action.
		if time.Since(onBatterySince) < onBatteryRequired {
			continue
		}

		if shutdownFired {
			continue
		}

		// Evaluate shutdown thresholds.
		policy := ups.ShutdownPolicy
		trigger := false
		switch policy.TriggerType {
		case "percent":
			if status.ChargePct != nil && *status.ChargePct <= float64(policy.PercentThreshold) {
				trigger = true
			}
		case "time":
			if status.RuntimeSecs != nil && *status.RuntimeSecs <= policy.RuntimeThreshold {
				trigger = true
			}
		case "both":
			percentMet := status.ChargePct != nil && *status.ChargePct <= float64(policy.PercentThreshold)
			timeMet := status.RuntimeSecs != nil && *status.RuntimeSecs <= policy.RuntimeThreshold
			trigger = percentMet || timeMet
		}

		if !trigger {
			continue
		}

		shutdownFired = true
		battSecs := int(time.Since(onBatterySince).Seconds())
		details := fmt.Sprintf("on battery for %ds; trigger=%s", battSecs, policy.TriggerType)
		if status.ChargePct != nil {
			details += fmt.Sprintf("; charge=%.0f%%", *status.ChargePct)
		}
		if status.RuntimeSecs != nil {
			details += fmt.Sprintf("; runtime=%ds", *status.RuntimeSecs)
		}
		if policy.PreShutdownCmd != "" {
			details += "; pre-cmd: " + policy.PreShutdownCmd
		}
		audit.Log(audit.Entry{
			User:    "system",
			Role:    "system",
			Action:  audit.ActionUPSShutdown,
			Result:  audit.ResultOK,
			Target:  ups.UPSName,
			Details: details,
		})
		log.Printf("UPS: initiating shutdown — %s", details)

		// Tell the user BEFORE anything starts stopping. This is the one moment
		// a UPS notification matters most, and it is also the last moment we can
		// send anything: below, the machine halts and this process SIGTERMs
		// itself, which would kill an in-flight send.
		{
			name := ups.UPSName
			if name == "" {
				name = "sysfs-battery"
			}
			reason := "battery threshold reached"
			switch policy.TriggerType {
			case "percent":
				reason = fmt.Sprintf("battery charge fell to the configured %d%% threshold", policy.PercentThreshold)
			case "time":
				reason = fmt.Sprintf("estimated runtime fell to the configured %ds threshold", policy.RuntimeThreshold)
			case "both":
				reason = fmt.Sprintf("battery reached a configured threshold (%d%% or %ds runtime)",
					policy.PercentThreshold, policy.RuntimeThreshold)
			}
			notifyUPSShutdown(name, reason, details)
		}

		if policy.PreShutdownCmd != "" {
			exec.Command("sh", "-c", policy.PreShutdownCmd).Run()
		}
		exec.Command("/sbin/shutdown", "-h", "+0").Run()

		// Stop zfsnas gracefully so connections close cleanly before the OS halts.
		syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}
}

// UninstallNUT stops and disables all NUT services, purges the nut packages,
// and removes the /etc/nut configuration directory.
func UninstallNUT() error {
	// Stop and disable services (tolerate errors — they may not be running).
	for _, svc := range []string{"nut-client", "nut-server", "nut-monitor"} {
		exec.Command("sudo", "systemctl", "stop", svc).Run()
		exec.Command("sudo", "systemctl", "disable", svc).Run()
	}

	// Purge packages so no residual config is left by apt.
	if out, err := exec.Command("sudo", "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "purge", "-y", "nut", "nut-client", "nut-server").CombinedOutput(); err != nil {
		// Try plain remove if purge fails (older apt versions).
		if out2, err2 := exec.Command("sudo", "env", "DEBIAN_FRONTEND=noninteractive",
			"apt-get", "remove", "-y", "nut", "nut-client").CombinedOutput(); err2 != nil {
			return fmt.Errorf("apt remove nut: %s", strings.TrimSpace(string(out)+string(out2)))
		}
		_ = out
	}

	// Remove the /etc/nut directory and all config files inside it.
	exec.Command("sudo", "rm", "-rf", "/etc/nut").Run()

	// Remove leftover nut-driver systemd unit fragments that apt purge leaves
	// behind. These include the target.wants directory, the template drop-in,
	// and any per-device drop-in directories (e.g. nut-driver@nutdev1.service.d).
	nutSystemdPaths := []string{
		"/etc/systemd/system/nut-driver.target.wants",
		"/etc/systemd/system/nut-driver@.service.d",
	}
	// Also glob any per-device drop-ins: nut-driver@<name>.service.d
	if entries, err := os.ReadDir("/etc/systemd/system"); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "nut-driver@") && strings.HasSuffix(e.Name(), ".service.d") {
				nutSystemdPaths = append(nutSystemdPaths, "/etc/systemd/system/"+e.Name())
			}
		}
	}
	for _, p := range nutSystemdPaths {
		exec.Command("sudo", "rm", "-rf", p).Run()
	}

	// Reload systemd so removed unit fragments no longer appear in unit state.
	exec.Command("sudo", "systemctl", "daemon-reload").Run()
	exec.Command("sudo", "systemctl", "reset-failed").Run()

	// The nut binaries are gone — drop them from the sticky presence cache so
	// UPSPrereqsInstalled() reports false immediately (top-bar UPS icon +
	// Optional Features page) instead of after the next service restart.
	ForgetBinaryPresence("upsc")
	ForgetBinaryPresence("upsd")

	return nil
}

// nutScannerOutput runs nut-scanner via sudo, capturing stdout only.
// stderr is intentionally discarded — nut-scanner writes library-not-found
// warnings and avahi/SNMP/XML/IPMI noise to stderr that must never appear
// in ups.conf.
func nutScannerOutput(bin string, args ...string) (string, error) {
	cmd := exec.Command("sudo", append([]string{bin}, args...)...)
	var stdout strings.Builder
	cmd.Stdout = &stdout
	// cmd.Stderr left nil → discarded
	err := cmd.Run()
	return stdout.String(), err
}

// fixNUTPermissions sets the standard ownership and mode for /etc/nut/ so
// that the nut daemon can read its config files.
func fixNUTPermissions() {
	exec.Command("sudo", "chown", "root:nut", "/etc/nut").Run()
	exec.Command("sudo", "chmod", "750", "/etc/nut").Run()
	for _, f := range []string{
		"/etc/nut/nut.conf",
		"/etc/nut/ups.conf",
		"/etc/nut/upsd.conf",
		"/etc/nut/upsd.users",
		"/etc/nut/upsmon.conf",
	} {
		exec.Command("sudo", "chown", "root:nut", f).Run()
		exec.Command("sudo", "chmod", "640", f).Run()
	}
}

// RestartNUTServices stops then starts nut-server and nut-client in the
// correct order, tolerating failures on distros with different unit names.
func RestartNUTServices() {
	for _, svc := range []string{"nut-client", "nut-server"} {
		exec.Command("sudo", "systemctl", "stop", svc).Run()
	}
	time.Sleep(500 * time.Millisecond)
	for _, svc := range []string{"nut-server", "nut-client"} {
		exec.Command("sudo", "systemctl", "start", svc).Run()
	}
}

// UPSServiceAction runs systemctl start|stop|restart on nut-server and nut-client.
func UPSServiceAction(action string) error {
	var svcs []string
	if action == "stop" {
		// Stop client before server
		svcs = []string{"nut-client", "nut-server"}
	} else {
		// Start/restart server before client
		svcs = []string{"nut-server", "nut-client"}
	}
	var lastErr error
	for _, svc := range svcs {
		if out, err := exec.Command("sudo", "systemctl", action, svc).CombinedOutput(); err != nil {
			lastErr = fmt.Errorf("systemctl %s %s: %s", action, svc, strings.TrimSpace(string(out)))
		}
	}
	return lastErr
}

// parseUPSUSBIDs extracts the vendorid and productid fields from nut-scanner
// -C output (INI format). Returns empty strings when not found (e.g. serial UPS).
func parseUPSUSBIDs(raw string) (vendorid, productid string) {
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := parseIniKV(line)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "vendorid":
			vendorid = strings.ToLower(v)
		case "productid":
			productid = strings.ToLower(v)
		}
		if vendorid != "" && productid != "" {
			return
		}
	}
	return
}

// writeNUTUdevRule creates /etc/udev/rules.d/62-nut-usbups.rules so that the
// nut group has read/write access to the USB UPS device. udev rules are
// reloaded and triggered immediately so the permission takes effect without a
// reboot. Errors from the trigger step are non-fatal.
func writeNUTUdevRule(vendorid, productid string) error {
	const path = "/etc/udev/rules.d/62-nut-usbups.rules"
	content := fmt.Sprintf(
		"# Generated by ZNAS — NUT USB UPS permissions\n"+
			"SUBSYSTEM==\"usb\", ATTRS{idVendor}==\"%s\", ATTRS{idProduct}==\"%s\", MODE=\"0660\", GROUP=\"nut\"\n",
		vendorid, productid,
	)
	if err := writeFileViaSudo(path, content, 0644); err != nil {
		return err
	}
	exec.Command("sudo", "udevadm", "control", "--reload-rules").Run()
	exec.Command("sudo", "udevadm", "trigger", "--subsystem-match=usb").Run()
	log.Printf("[ups] udev rule written: %s (vendor=%s product=%s)", path, vendorid, productid)
	return nil
}

// writeFileViaSudo writes content to path using sudo tee.
func writeFileViaSudo(path, content string, _ os.FileMode) error {
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tee %s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}
