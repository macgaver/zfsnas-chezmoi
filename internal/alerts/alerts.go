package alerts

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zfsnas/internal/secret"
)

// ── Event keys ────────────────────────────────────────────────────────────────

type EventKey string

const (
	EventPoolDegraded    EventKey = "pool_degraded"
	EventSmartError      EventKey = "smart_error"
	EventWearoutExceeded EventKey = "wearout_exceeded"
	EventFailedLogin     EventKey = "failed_login_alert"
	EventSecurityUpdates EventKey = "security_updates"
	EventScrubErrors     EventKey = "scrub_errors"
	EventSnapshotFailure    EventKey = "snapshot_failure"
	EventReplicationFailure EventKey = "replication_failure"
	EventUserCreated        EventKey = "user_created_deleted"
	EventShareCreated    EventKey = "share_created_deleted"
	EventPoolActions     EventKey = "pool_actions"
	EventVMStartFailure     EventKey = "vm_start_failure"
	EventVMUnexpectedStop   EventKey = "vm_unexpected_stop"
	EventVMCreatedDeleted   EventKey = "vm_created_deleted"
	EventVMSnapshotFailure  EventKey = "vm_snapshot_failure"
	EventVMBackupFailure    EventKey = "vm_backup_failure"
	EventVMDiskFull         EventKey = "vm_disk_full"
	EventVMHostSaturation   EventKey = "vm_host_saturation"
	EventComposeUpdateFailure EventKey = "compose_update_failure"
	EventInterlinkUnreachable EventKey = "interlink_unreachable"
	EventUPSPowerChanged      EventKey = "ups_power_changed"
	EventTest            EventKey = "test" // always passes filter
)

// matchesEvent reports whether the event key is enabled in the given EventConfig.
func matchesEvent(key EventKey, ev EventConfig) bool {
	if key == EventTest {
		return true
	}
	switch key {
	case EventPoolDegraded:    return ev.PoolDegraded
	case EventSmartError:      return ev.SmartError
	case EventWearoutExceeded: return ev.WearoutExceeded
	case EventFailedLogin:     return ev.FailedLoginAlert
	case EventSecurityUpdates: return ev.SecurityUpdates
	case EventScrubErrors:     return ev.ScrubErrors
	case EventSnapshotFailure:    return ev.SnapshotFailure
	case EventReplicationFailure: return ev.ReplicationFailure
	case EventUserCreated:        return ev.UserCreatedDeleted
	case EventShareCreated:    return ev.ShareCreatedDeleted
	case EventPoolActions:     return ev.PoolActions
	case EventVMStartFailure:    return ev.VMStartFailure
	case EventVMUnexpectedStop:  return ev.VMUnexpectedStop
	case EventVMCreatedDeleted:  return ev.VMCreatedDeleted
	case EventVMSnapshotFailure: return ev.VMSnapshotFailure
	case EventVMBackupFailure:   return ev.VMBackupFailure
	case EventVMDiskFull:        return ev.VMDiskFull
	case EventVMHostSaturation:  return ev.VMHostSaturation
	case EventComposeUpdateFailure: return ev.ComposeUpdateFailure
	case EventInterlinkUnreachable: return ev.InterlinkUnreachable
	case EventUPSPowerChanged:      return ev.UPSPowerChanged
	}
	return false
}

// AnyTargetWants reports whether at least one enabled target subscribes to the
// given event key. Used by background pollers to skip checks nobody would receive.
func AnyTargetWants(cfg *AlertConfig, key EventKey) bool {
	for _, ev := range allEnabledEvents(cfg) {
		if matchesEvent(key, ev) {
			return true
		}
	}
	return false
}

// ── Config types ──────────────────────────────────────────────────────────────

// SMTPConfig holds SMTP connection parameters.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	From     string `json:"from"`
	AuthMode string `json:"auth_mode"` // none | plain | starttls | tls
	Username string `json:"username"`
	Password string `json:"password"`
}

// EventConfig holds per-event subscription flags and thresholds.
type EventConfig struct {
	PoolDegraded         bool `json:"pool_degraded"`
	SmartError           bool `json:"smart_error"`
	WearoutExceeded      bool `json:"wearout_exceeded"`
	WearoutThresholdPct  int  `json:"wearout_threshold_pct"`
	FailedLoginAlert     bool `json:"failed_login_alert"`
	FailedLoginThreshold int  `json:"failed_login_threshold"`
	SecurityUpdates      bool `json:"security_updates"`
	ScrubErrors          bool `json:"scrub_errors"`
	SnapshotFailure      bool `json:"snapshot_failure"`
	ReplicationFailure   bool `json:"replication_failure"`
	UserCreatedDeleted   bool `json:"user_created_deleted"`
	ShareCreatedDeleted  bool `json:"share_created_deleted"`
	PoolActions          bool `json:"pool_actions"`
	InterlinkUnreachable bool `json:"interlink_unreachable"`
	UPSPowerChanged      bool `json:"ups_power_changed"`

	// Virtualization events — only meaningful when the optional LXD/Incus
	// feature is installed. Hidden in the UI on servers without it but kept
	// in the persisted JSON so subscriptions survive an LXD reinstall.
	VMStartFailure          bool `json:"vm_start_failure"`
	VMUnexpectedStop        bool `json:"vm_unexpected_stop"`
	VMCreatedDeleted        bool `json:"vm_created_deleted"`
	VMSnapshotFailure       bool `json:"vm_snapshot_failure"`
	VMBackupFailure         bool `json:"vm_backup_failure"`
	VMDiskFull              bool `json:"vm_disk_full"`
	VMDiskFullThresholdPct  int  `json:"vm_disk_full_threshold_pct"`
	VMHostSaturation        bool `json:"vm_host_saturation"`
	ComposeUpdateFailure    bool `json:"compose_update_failure"`
}

type EmailTarget struct {
	Enabled        bool        `json:"enabled"`
	SMTP           SMTPConfig  `json:"smtp"`
	To             []string    `json:"to"`
	SendSeparately bool        `json:"send_separately"`
	Events         EventConfig `json:"events"`
}

type NtfyTarget struct {
	Enabled  bool        `json:"enabled"`
	URL      string      `json:"url"`      // full topic URL, e.g. https://ntfy.sh/mytopic
	Token    string      `json:"token"`    // optional Bearer token
	Priority string      `json:"priority"` // default | low | high | urgent
	Events   EventConfig `json:"events"`
}

type GotifyTarget struct {
	Enabled  bool        `json:"enabled"`
	URL      string      `json:"url"`      // server root, e.g. https://gotify.example.com
	Token    string      `json:"token"`    // app token
	Priority int         `json:"priority"` // 1–10
	Events   EventConfig `json:"events"`
}

type PushoverTarget struct {
	Enabled  bool        `json:"enabled"`
	UserKey  string      `json:"user_key"`
	APIToken string      `json:"api_token"`
	Device   string      `json:"device"`   // optional; blank = all devices
	Priority int         `json:"priority"` // -2 to 2
	Events   EventConfig `json:"events"`
}

type SyslogTarget struct {
	Enabled  bool        `json:"enabled"`
	Host     string      `json:"host"`
	Port     int         `json:"port"`      // default 514
	Protocol string      `json:"protocol"`  // udp | tcp
	Facility string      `json:"facility"`  // user | daemon | local0–local7
	Tag      string      `json:"tag"`       // syslog tag / app name
	Events   EventConfig `json:"events"`
}

// WebSocketTarget broadcasts alert payloads to all browser sessions open in the portal.
type WebSocketTarget struct {
	Enabled bool        `json:"enabled"`
	Events  EventConfig `json:"events"`
}

// AlertConfig is the root alert configuration persisted to alerts.json.
type AlertConfig struct {
	Email     EmailTarget     `json:"email"`
	Ntfy      NtfyTarget      `json:"ntfy"`
	Gotify    GotifyTarget    `json:"gotify"`
	Pushover  PushoverTarget  `json:"pushover"`
	Syslog    SyslogTarget    `json:"syslog"`
	WebSocket WebSocketTarget `json:"websocket"`
}

// ── Package-level state ───────────────────────────────────────────────────────

var (
	configDir    string
	mu           sync.RWMutex
	failedLogins int64
	smtpKey      []byte
	wsHub        *AlertsHub
)

// SetWSHub wires the in-app WebSocket broadcast hub.
func SetWSHub(h *AlertsHub) { wsHub = h }

// GetHub returns the registered AlertsHub (may be nil if not wired).
func GetHub() *AlertsHub { return wsHub }

// Init sets the config directory and loads (or creates) the SMTP encryption key.
func Init(dir string) {
	configDir = dir
	keyPath := filepath.Join(dir, "smtp.key")
	key, err := secret.LoadOrCreateKey(keyPath)
	if err != nil {
		log.Printf("[alerts] warning: could not load/create SMTP key: %v — password will be stored unencrypted", err)
		return
	}
	smtpKey = key
}

func defaultEventConfig() EventConfig {
	return EventConfig{
		PoolDegraded:         true,
		SmartError:           true,
		WearoutExceeded:      true,
		WearoutThresholdPct:  80,
		FailedLoginAlert:     true,
		FailedLoginThreshold: 5,
		ScrubErrors:          true,
		SnapshotFailure:      true,
		ReplicationFailure:   true,
		InterlinkUnreachable: true,
	}
}

func defaultConfig() *AlertConfig {
	ev := defaultEventConfig()
	return &AlertConfig{
		Email:     EmailTarget{SMTP: SMTPConfig{Port: 587, AuthMode: "starttls"}, Events: ev},
		Ntfy:      NtfyTarget{Priority: "default", Events: ev},
		Gotify:    GotifyTarget{Priority: 5, Events: ev},
		Pushover:  PushoverTarget{Events: ev},
		Syslog:    SyslogTarget{Port: 514, Protocol: "udp", Facility: "daemon", Tag: "zfsnas", Events: ev},
		WebSocket: WebSocketTarget{Events: ev},
	}
}

// ── Load / Save ───────────────────────────────────────────────────────────────

// Load reads alert config from disk. If the file is in the old format (root-level
// smtp/to/events) it is automatically migrated to the new multi-target format.
func Load() (*AlertConfig, error) {
	path := filepath.Join(configDir, "alerts.json")

	mu.RLock()
	data, err := os.ReadFile(path)
	mu.RUnlock()

	if os.IsNotExist(err) {
		return defaultConfig(), nil
	}
	if err != nil {
		return nil, err
	}

	// Detect legacy format: has root-level "smtp" key but no "email" key.
	var probe struct {
		Email *json.RawMessage `json:"email"`
	}
	json.Unmarshal(data, &probe) //nolint:errcheck

	if probe.Email == nil {
		// Legacy migration.
		var legacy struct {
			SMTP   SMTPConfig  `json:"smtp"`
			To     []string    `json:"to"`
			Events EventConfig `json:"events"`
		}
		if err := json.Unmarshal(data, &legacy); err != nil {
			return nil, err
		}
		cfg := defaultConfig()
		cfg.Email.SMTP = legacy.SMTP
		cfg.Email.To = legacy.To
		cfg.Email.Events = legacy.Events
		cfg.Email.Enabled = legacy.SMTP.Host != ""
		if smtpKey != nil && secret.IsEncrypted(cfg.Email.SMTP.Password) {
			if plain, decErr := secret.Decrypt(smtpKey, cfg.Email.SMTP.Password); decErr == nil {
				cfg.Email.SMTP.Password = plain
			}
		}
		go Save(cfg) // persist migration asynchronously
		return cfg, nil
	}

	// New format.
	cfg := defaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if smtpKey != nil && secret.IsEncrypted(cfg.Email.SMTP.Password) {
		if plain, decErr := secret.Decrypt(smtpKey, cfg.Email.SMTP.Password); decErr == nil {
			cfg.Email.SMTP.Password = plain
		}
	}
	return cfg, nil
}

// Save persists alert config to disk, encrypting the SMTP password if a key is available.
func Save(cfg *AlertConfig) error {
	mu.Lock()
	defer mu.Unlock()

	toWrite := *cfg
	if smtpKey != nil && toWrite.Email.SMTP.Password != "" && !secret.IsEncrypted(toWrite.Email.SMTP.Password) {
		enc, err := secret.Encrypt(smtpKey, toWrite.Email.SMTP.Password)
		if err != nil {
			return fmt.Errorf("encrypt SMTP password: %w", err)
		}
		toWrite.Email.SMTP.Password = enc
	}

	path := filepath.Join(configDir, "alerts.json")
	data, err := json.MarshalIndent(toWrite, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}

// ── Failed login counter ──────────────────────────────────────────────────────

// RecordFailedLogin increments the failed-login counter and, if the
// configured threshold is reached, immediately fires the alert and resets
// the counter. The standalone 5-min health poller also checks the counter,
// but waiting up to 5 min for a "1 attempt" alert is useless — and any
// subsequent successful login resets the counter to 0 before the poller
// runs, masking the failure. Doing the check inline closes that gap.
func RecordFailedLogin() {
	count := atomic.AddInt64(&failedLogins, 1)
	go checkFailedLoginThresholdAt(count)
}

func ResetFailedLogins()      { atomic.StoreInt64(&failedLogins, 0) }
func FailedLoginCount() int64 { return atomic.LoadInt64(&failedLogins) }

func checkFailedLoginThresholdAt(count int64) {
	cfg, err := Load()
	if err != nil {
		return
	}
	enabled, threshold := MinFailedLoginThreshold(cfg)
	if !enabled || threshold <= 0 || count < int64(threshold) {
		return
	}
	// Reset first to avoid duplicate alerts on a racing concurrent failure.
	ResetFailedLogins()
	if err := Send(
		EventFailedLogin,
		fmt.Sprintf("Failed logins: %d attempts", count),
		"Failed Login Threshold Exceeded",
		fmt.Sprintf("%d failed login attempt(s) were detected.", count),
	); err != nil {
		log.Printf("[alerts] failed-login alert send: %v", err)
	}
}

// ── Threshold helpers (used by health poller) ─────────────────────────────────

// MinWearoutThreshold returns the lowest non-zero wearout threshold across all
// enabled targets that have WearoutExceeded enabled, and whether any exist.
func MinWearoutThreshold(cfg *AlertConfig) (enabled bool, pct int) {
	for _, ev := range allEnabledEvents(cfg) {
		if ev.WearoutExceeded && ev.WearoutThresholdPct > 0 {
			if pct == 0 || ev.WearoutThresholdPct < pct {
				pct = ev.WearoutThresholdPct
				enabled = true
			}
		}
	}
	return
}

// MinFailedLoginThreshold returns the lowest non-zero failed-login threshold
// across all enabled targets that have FailedLoginAlert enabled.
func MinFailedLoginThreshold(cfg *AlertConfig) (enabled bool, threshold int) {
	for _, ev := range allEnabledEvents(cfg) {
		if ev.FailedLoginAlert && ev.FailedLoginThreshold > 0 {
			if threshold == 0 || ev.FailedLoginThreshold < threshold {
				threshold = ev.FailedLoginThreshold
				enabled = true
			}
		}
	}
	return
}

func allEnabledEvents(cfg *AlertConfig) []EventConfig {
	var evs []EventConfig
	if cfg.Email.Enabled     { evs = append(evs, cfg.Email.Events) }
	if cfg.Ntfy.Enabled      { evs = append(evs, cfg.Ntfy.Events) }
	if cfg.Gotify.Enabled    { evs = append(evs, cfg.Gotify.Events) }
	if cfg.Pushover.Enabled  { evs = append(evs, cfg.Pushover.Events) }
	if cfg.Syslog.Enabled    { evs = append(evs, cfg.Syslog.Events) }
	if cfg.WebSocket.Enabled { evs = append(evs, cfg.WebSocket.Events) }
	return evs
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

// Send dispatches an alert to all enabled targets that subscribe to the given event key.
func Send(key EventKey, subject, event, details string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	now := time.Now().Format("2006-01-02 15:04:05 MST")

	if cfg.Email.Enabled && matchesEvent(key, cfg.Email.Events) {
		go func() {
			if err := sendEmail(cfg, subject, event, details, hostname); err != nil {
				log.Printf("[alerts/email] %v", err)
			}
		}()
	}
	if cfg.Ntfy.Enabled && matchesEvent(key, cfg.Ntfy.Events) {
		go func() {
			if err := sendNtfy(cfg.Ntfy, subject, event, details, hostname); err != nil {
				log.Printf("[alerts/ntfy] %v", err)
			}
		}()
	}
	if cfg.Gotify.Enabled && matchesEvent(key, cfg.Gotify.Events) {
		go func() {
			if err := sendGotify(cfg.Gotify, subject, event, details, hostname); err != nil {
				log.Printf("[alerts/gotify] %v", err)
			}
		}()
	}
	if cfg.Pushover.Enabled && matchesEvent(key, cfg.Pushover.Events) {
		go func() {
			if err := sendPushover(cfg.Pushover, subject, event, details, hostname); err != nil {
				log.Printf("[alerts/pushover] %v", err)
			}
		}()
	}
	if cfg.Syslog.Enabled && matchesEvent(key, cfg.Syslog.Events) {
		go func() {
			if err := sendSyslogMsg(cfg.Syslog, subject, event, details, hostname); err != nil {
				log.Printf("[alerts/syslog] %v", err)
			}
		}()
	}
	if cfg.WebSocket.Enabled && matchesEvent(key, cfg.WebSocket.Events) && wsHub != nil {
		wsHub.BroadcastJSON(map[string]string{
			"subject":  subject,
			"event":    event,
			"details":  details,
			"hostname": hostname,
			"time":     now,
		})
	}
	return nil
}

// ── Per-target test functions (used by handlers; ignore enabled flag) ─────────

func TestEmail() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	return sendEmail(cfg, "Test Alert", "Manual Test", "This is a test alert from the ZFS NAS management portal.", hostname)
}

func TestNtfy() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	return sendNtfy(cfg.Ntfy, "Test Alert", "Manual Test", "This is a test notification from the ZFS NAS management portal.", hostname)
}

func TestGotify() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	return sendGotify(cfg.Gotify, "Test Alert", "Manual Test", "This is a test notification from the ZFS NAS management portal.", hostname)
}

func TestPushover() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	return sendPushover(cfg.Pushover, "Test Alert", "Manual Test", "This is a test notification from the ZFS NAS management portal.", hostname)
}

func TestSyslog() error {
	cfg, err := Load()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	return sendSyslogMsg(cfg.Syslog, "Test Alert", "Manual Test", "This is a test from the ZFS NAS management portal.", hostname)
}

func TestWebSocket() {
	if wsHub == nil {
		return
	}
	hostname, _ := os.Hostname()
	wsHub.BroadcastJSON(map[string]string{
		"subject":  "Test Alert",
		"event":    "Manual Test",
		"details":  "This is a test in-app notification from the ZFS NAS management portal.",
		"hostname": hostname,
		"time":     time.Now().Format("2006-01-02 15:04:05 MST"),
	})
}

// ── Email sender ──────────────────────────────────────────────────────────────

func sendEmail(cfg *AlertConfig, subject, event, details, hostname string) error {
	if cfg.Email.SMTP.Host == "" || len(cfg.Email.To) == 0 {
		return nil
	}
	body, err := renderEmail(emailData{
		Event:    event,
		Details:  details,
		Hostname: hostname,
		Time:     time.Now().Format("2006-01-02 15:04:05 MST"),
	})
	if err != nil {
		return err
	}
	return sendSMTP(&cfg.Email, subject, body)
}

func sendSMTP(t *EmailTarget, subject, htmlBody string) error {
	if t.SendSeparately && len(t.To) > 1 {
		var errs []string
		for _, recipient := range t.To {
			if err := sendSMTPToRecipients(t, []string{recipient}, subject, htmlBody); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", recipient, err))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("some recipients failed: %s", strings.Join(errs, "; "))
		}
		return nil
	}
	return sendSMTPToRecipients(t, t.To, subject, htmlBody)
}

func sendSMTPToRecipients(t *EmailTarget, recipients []string, subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", t.SMTP.Host, t.SMTP.Port)
	msg := buildMIME(t.SMTP.From, recipients, subject, htmlBody)

	switch t.SMTP.AuthMode {
	case "none":
		return smtp.SendMail(addr, nil, t.SMTP.From, recipients, msg)
	case "plain", "starttls":
		auth := smtp.PlainAuth("", t.SMTP.Username, t.SMTP.Password, t.SMTP.Host)
		return smtp.SendMail(addr, auth, t.SMTP.From, recipients, msg)
	case "tls":
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: t.SMTP.Host})
		if err != nil {
			return err
		}
		c, err := smtp.NewClient(conn, t.SMTP.Host)
		if err != nil {
			return err
		}
		defer c.Quit() //nolint
		if t.SMTP.Username != "" {
			auth := smtp.PlainAuth("", t.SMTP.Username, t.SMTP.Password, t.SMTP.Host)
			if err := c.Auth(auth); err != nil {
				return err
			}
		}
		if err := c.Mail(t.SMTP.From); err != nil {
			return err
		}
		for _, r := range recipients {
			if err := c.Rcpt(r); err != nil {
				return err
			}
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		if _, err := w.Write(msg); err != nil {
			return err
		}
		return w.Close()
	}
	return fmt.Errorf("unknown auth_mode: %s", t.SMTP.AuthMode)
}

func buildMIME(from string, to []string, subject, htmlBody string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	for _, t := range to {
		fmt.Fprintf(&buf, "To: %s\r\n", t)
	}
	fmt.Fprintf(&buf, "Subject: [ZFS NAS] %s\r\n", subject)
	fmt.Fprintf(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: text/html; charset=UTF-8\r\n")
	fmt.Fprintf(&buf, "\r\n")
	fmt.Fprintf(&buf, "%s", htmlBody)
	return buf.Bytes()
}

// ── ntfy sender ───────────────────────────────────────────────────────────────

func sendNtfy(t NtfyTarget, subject, event, details, hostname string) error {
	if t.URL == "" {
		return nil
	}
	body := fmt.Sprintf("Event: %s\nDetails: %s\nHost: %s\nTime: %s",
		event, details, hostname, time.Now().Format("2006-01-02 15:04:05 MST"))
	req, err := http.NewRequest(http.MethodPost, t.URL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Title", "[ZFS NAS] "+subject)
	req.Header.Set("X-Tags", "warning")
	if t.Priority != "" && t.Priority != "default" {
		req.Header.Set("X-Priority", t.Priority)
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ntfy returned status %d", resp.StatusCode)
	}
	return nil
}

// ── Gotify sender ─────────────────────────────────────────────────────────────

func sendGotify(t GotifyTarget, subject, event, details, hostname string) error {
	if t.URL == "" || t.Token == "" {
		return nil
	}
	prio := t.Priority
	if prio == 0 {
		prio = 5
	}
	msgBody := fmt.Sprintf("%s\n\nHost: %s\nTime: %s",
		details, hostname, time.Now().Format("2006-01-02 15:04:05 MST"))
	payload, _ := json.Marshal(map[string]interface{}{
		"title":    "[ZFS NAS] " + subject,
		"message":  msgBody,
		"priority": prio,
	})
	endpoint := strings.TrimRight(t.URL, "/") + "/message?token=" + url.QueryEscape(t.Token)
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("gotify returned status %d", resp.StatusCode)
	}
	return nil
}

// ── Pushover sender ───────────────────────────────────────────────────────────

func sendPushover(t PushoverTarget, subject, event, details, hostname string) error {
	if t.UserKey == "" || t.APIToken == "" {
		return nil
	}
	msgBody := fmt.Sprintf("%s\n\nHost: %s\nTime: %s",
		details, hostname, time.Now().Format("2006-01-02 15:04:05 MST"))
	vals := url.Values{
		"token":    {t.APIToken},
		"user":     {t.UserKey},
		"title":    {"[ZFS NAS] " + subject},
		"message":  {msgBody},
		"priority": {fmt.Sprintf("%d", t.Priority)},
	}
	if t.Device != "" {
		vals.Set("device", t.Device)
	}
	resp, err := http.PostForm("https://api.pushover.net/1/messages.json", vals)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}
	return nil
}

// ── Syslog sender (raw RFC 3164, direct net.Dial) ─────────────────────────────

// syslogPRI computes the RFC 3164 PRI value: (facility << 3) | severity.
// Severity 4 = Warning.
func syslogPRI(facility string) int {
	fac := 3 // daemon
	switch facility {
	case "user":   fac = 1
	case "local0": fac = 16
	case "local1": fac = 17
	case "local2": fac = 18
	case "local3": fac = 19
	case "local4": fac = 20
	case "local5": fac = 21
	case "local6": fac = 22
	case "local7": fac = 23
	}
	return (fac * 8) + 4 // severity 4 = Warning
}

func sendSyslogMsg(t SyslogTarget, subject, event, details, hostname string) error {
	if t.Host == "" {
		return fmt.Errorf("syslog host is not configured")
	}
	port := t.Port
	if port == 0 {
		port = 514
	}
	proto := strings.ToLower(t.Protocol)
	if proto == "" {
		proto = "udp"
	}
	tag := t.Tag
	if tag == "" {
		tag = "zfsnas"
	}
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	addr := fmt.Sprintf("%s:%d", t.Host, port)
	conn, err := net.DialTimeout(proto, addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("syslog dial %s %s: %w", proto, addr, err)
	}
	defer conn.Close()

	// RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG
	ts  := time.Now().Format("Jan _2 15:04:05")
	msg := fmt.Sprintf("[ZFS NAS] %s | event=%s | details=%s", subject, event, details)
	pkt := fmt.Sprintf("<%d>%s %s %s[%d]: %s\n",
		syslogPRI(t.Facility), ts, hostname, tag, os.Getpid(), msg)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(pkt))
	return err
}

// ── Email HTML template ───────────────────────────────────────────────────────

type emailData struct {
	Event    string
	Details  string
	Hostname string
	Time     string
}

var emailTmpl = template.Must(template.New("email").Parse(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d0d0f;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <div style="max-width:560px;margin:32px auto;border-radius:12px;overflow:hidden;border:1px solid #2a2a35;">
    <div style="background:linear-gradient(135deg,#bf5af2,#6e40c9);padding:20px 28px;">
      <div style="color:#fff;font-size:20px;font-weight:700;">ZFS NAS Alert</div>
      <div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:4px;">{{.Event}}</div>
    </div>
    <div style="background:#161619;padding:28px;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;color:#e5e5ea;">
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;color:#8e8e93;width:38%;">Event</td>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;font-weight:600;">{{.Event}}</td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;color:#8e8e93;">Details</td>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;">{{.Details}}</td>
        </tr>
        <tr>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;color:#8e8e93;">Host</td>
          <td style="padding:10px 0;border-bottom:1px solid #2a2a35;font-family:monospace;">{{.Hostname}}</td>
        </tr>
        <tr>
          <td style="padding:10px 0;color:#8e8e93;">Time</td>
          <td style="padding:10px 0;font-family:monospace;">{{.Time}}</td>
        </tr>
      </table>
    </div>
    <div style="background:#0d0d0f;padding:14px 28px;font-size:11px;color:#48484a;border-top:1px solid #2a2a35;">
      Sent by ZFS NAS Management Portal &middot; {{.Hostname}}
    </div>
  </div>
</body></html>`))

func renderEmail(d emailData) (string, error) {
	var buf bytes.Buffer
	if err := emailTmpl.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}
