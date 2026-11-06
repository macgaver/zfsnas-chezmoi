package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// HandleListReplicationTasks returns all configured replication tasks.
func HandleListReplicationTasks(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, cfg.Replication)
}

// HandleCreateReplicationTask creates a new replication task.
func HandleCreateReplicationTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		SourceDataset string `json:"source_dataset"`
		RemoteHost    string `json:"remote_host"`
		RemoteUser    string `json:"remote_user"`
		RemoteDataset string `json:"remote_dataset"`
		Recursive     bool   `json:"recursive"`
		Compressed    bool   `json:"compressed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" || req.SourceDataset == "" || req.RemoteHost == "" || req.RemoteDataset == "" {
		jsonErr(w, http.StatusBadRequest, "name, source_dataset, remote_host and remote_dataset are required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	task := config.ReplicationTask{
		ID:            newID(),
		Name:          req.Name,
		SourceDataset: req.SourceDataset,
		RemoteHost:    req.RemoteHost,
		RemoteUser:    req.RemoteUser,
		RemoteDataset: req.RemoteDataset,
		Recursive:     req.Recursive,
		Compressed:    req.Compressed,
		LastStatus:    "never",
	}
	cfg.Replication = append(cfg.Replication, task)

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionCreateReplication,
		Target: task.Name,
		Result: audit.ResultOK,
	})
	jsonOK(w, task)
}

// HandleEditReplicationTask updates an existing replication task by ID.
func HandleEditReplicationTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Name          string `json:"name"`
		SourceDataset string `json:"source_dataset"`
		RemoteHost    string `json:"remote_host"`
		RemoteUser    string `json:"remote_user"`
		RemoteDataset string `json:"remote_dataset"`
		Recursive     bool   `json:"recursive"`
		Compressed    bool   `json:"compressed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Name == "" || req.SourceDataset == "" || req.RemoteHost == "" || req.RemoteDataset == "" {
		jsonErr(w, http.StatusBadRequest, "name, source_dataset, remote_host and remote_dataset are required")
		return
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	found := false
	for i, t := range cfg.Replication {
		if t.ID == id {
			cfg.Replication[i].Name = req.Name
			cfg.Replication[i].SourceDataset = req.SourceDataset
			cfg.Replication[i].RemoteHost = req.RemoteHost
			cfg.Replication[i].RemoteUser = req.RemoteUser
			cfg.Replication[i].RemoteDataset = req.RemoteDataset
			cfg.Replication[i].Recursive = req.Recursive
			cfg.Replication[i].Compressed = req.Compressed
			found = true
			break
		}
	}
	if !found {
		jsonErr(w, http.StatusNotFound, "task not found")
		return
	}

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionEditReplication,
		Target: req.Name,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleDeleteReplicationTask deletes a replication task by ID.
func HandleDeleteReplicationTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	cfg, err := config.LoadAppConfig()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var name string
	tasks := cfg.Replication[:0]
	for _, t := range cfg.Replication {
		if t.ID == id {
			name = t.Name
			continue
		}
		tasks = append(tasks, t)
	}
	if name == "" {
		jsonErr(w, http.StatusNotFound, "task not found")
		return
	}
	cfg.Replication = tasks

	if err := config.SaveAppConfig(cfg); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteReplication,
		Target: name,
		Result: audit.ResultOK,
	})
	jsonOK(w, map[string]bool{"ok": true})
}

// HandleRunReplicationTask upgrades to WebSocket and streams replication output.
func HandleRunReplicationTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	send := func(line string) {
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"line": line,
		}))
	}
	done := func(success bool, msg string) {
		conn.WriteMessage(websocket.TextMessage, mustJSON(map[string]interface{}{
			"done":    true,
			"success": success,
			"message": msg,
		}))
	}

	cfg, err := config.LoadAppConfig()
	if err != nil {
		done(false, "failed to load config: "+err.Error())
		return
	}

	var taskIdx int = -1
	for i, t := range cfg.Replication {
		if t.ID == id {
			taskIdx = i
			break
		}
	}
	if taskIdx < 0 {
		done(false, "task not found")
		return
	}
	task := &cfg.Replication[taskIdx]

	send(fmt.Sprintf("Starting replication: %s → %s@%s:%s", task.SourceDataset, task.RemoteUser, task.RemoteHost, task.RemoteDataset))

	newSnap, runErr := system.RunReplication(task, send, "")

	send("─────────────────────────────────────────")

	task.LastRun = time.Now()
	sess := MustSession(r)

	if runErr != nil {
		task.LastStatus = "error"
		task.LastMessage = runErr.Error()
		send("Replication failed: " + runErr.Error())
		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionRunReplication,
			Target:  task.Name,
			Result:  audit.ResultError,
			Details: runErr.Error(),
		})
		config.SaveAppConfig(cfg)
		done(false, runErr.Error())
		return
	}

	task.LastSnap = newSnap
	task.LastStatus = "ok"
	task.LastMessage = ""
	send("Replication completed successfully.")
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionRunReplication,
		Target: task.Name,
		Result: audit.ResultOK,
	})
	config.SaveAppConfig(cfg)
	done(true, "replication complete")
}
