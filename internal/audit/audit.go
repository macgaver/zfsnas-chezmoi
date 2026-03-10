package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single audit log event.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Result    string    `json:"result"` // "ok" or "error"
	Details   string    `json:"details,omitempty"`
}

const (
	ResultOK    = "ok"
	ResultError = "error"
)

// Common action names.
const (
	ActionLogin        = "login"
	ActionLogout       = "logout"
	ActionLoginFailed  = "login_failed"
	ActionSetupAdmin   = "setup_admin"
	ActionCreateUser   = "create_user"
	ActionDeleteUser   = "delete_user"
	ActionUpdateUser   = "update_user"
	ActionKillSession  = "kill_session"
	ActionCreatePool   = "create_pool"
	ActionImportPool   = "import_pool"
	ActionCreateDataset = "create_dataset"
	ActionUpdateDataset = "update_dataset"
	ActionDeleteDataset = "delete_dataset"
	ActionCreateShare  = "create_share"
	ActionDeleteShare  = "delete_share"
	ActionEnableShare  = "enable_share"
	ActionDisableShare = "disable_share"
	ActionCreateSnapshot = "create_snapshot"
	ActionDeleteSnapshot = "delete_snapshot"
	ActionRestoreSnapshot = "restore_snapshot"
	ActionInstallPrereqs = "install_prereqs"
	ActionInstallService = "install_service"
	ActionApplyUpdates  = "apply_updates"
	ActionGrowPool      = "grow_pool"
	ActionDestroyPool   = "destroy_pool"
	ActionUpdateSettings = "update_settings"
	ActionCreateNFSShare  = "create_nfs_share"
	ActionUpdateNFSShare  = "update_nfs_share"
	ActionDeleteNFSShare  = "delete_nfs_share"
	ActionCreateSchedule  = "create_schedule"
	ActionUpdateSchedule  = "update_schedule"
	ActionDeleteSchedule  = "delete_schedule"
)

var (
	logPath string
	mu      sync.Mutex
)

// Init sets the audit log file path.
func Init(configDir string) {
	logPath = filepath.Join(configDir, "audit.log")
}

// Log appends an entry to the audit log.
func Log(e Entry) {
	e.Timestamp = time.Now()
	mu.Lock()
	defer mu.Unlock()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to open log: %v\n", err)
		return
	}
	defer f.Close()

	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "%s\n", data)
}

// Read loads all audit entries from the log file.
func Read() ([]Entry, error) {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}

	var entries []Entry
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err == nil {
			entries = append(entries, e)
		}
	}
	return entries, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
