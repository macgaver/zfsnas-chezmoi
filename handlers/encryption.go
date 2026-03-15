package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/keystore"
	"zfsnas/system"

	"github.com/gorilla/mux"
)

// HandleListKeys returns all encryption key metadata.
func HandleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	jsonOK(w, keys)
}

// HandleGenerateKey creates a new 32-byte random encryption key.
// Body: {"name": "friendly name"}
func HandleGenerateKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "name is required")
		return
	}

	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}

	entry := config.EncryptionKey{
		ID:        newID(),
		Name:      req.Name,
		CreatedAt: time.Now(),
	}
	if err := keystore.GenerateKey(entry.ID); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to generate key: "+err.Error())
		return
	}
	keys = append(keys, entry)
	if err := config.SaveEncryptionKeys(keys); err != nil {
		// Try to clean up the key file if metadata save fails.
		keystore.DeleteKey(entry.ID)
		jsonErr(w, http.StatusInternalServerError, "failed to save key metadata")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionGenerateKey,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	jsonCreated(w, entry)
}

// HandleImportKey imports a key from a hex-encoded string.
// Body: {"name": "...", "key_hex": "<64 hex chars = 32 bytes>"}
func HandleImportKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		KeyHex string `json:"key_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		jsonErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.KeyHex == "" {
		jsonErr(w, http.StatusBadRequest, "key_hex is required")
		return
	}

	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}

	entry := config.EncryptionKey{
		ID:        newID(),
		Name:      req.Name,
		CreatedAt: time.Now(),
	}
	if err := keystore.ImportKeyHex(entry.ID, req.KeyHex); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	keys = append(keys, entry)
	if err := config.SaveEncryptionKeys(keys); err != nil {
		keystore.DeleteKey(entry.ID)
		jsonErr(w, http.StatusInternalServerError, "failed to save key metadata")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionImportKey,
		Target: req.Name,
		Result: audit.ResultOK,
	})

	jsonCreated(w, entry)
}

// HandleExportKey returns the raw key bytes as a file download.
func HandleExportKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	var entry *config.EncryptionKey
	for i := range keys {
		if keys[i].ID == id {
			entry = &keys[i]
			break
		}
	}
	if entry == nil {
		jsonErr(w, http.StatusNotFound, "key not found")
		return
	}

	hexStr, err := keystore.ExportKeyHex(id)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to read key file: "+err.Error())
		return
	}

	payload, _ := json.Marshal(map[string]string{entry.Name: hexStr})
	filename := entry.Name + ".json"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write(payload)
}

// HandleDeleteKey deletes a key if it is not in use by any pool or dataset.
func HandleDeleteKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	var entry *config.EncryptionKey
	for i := range keys {
		if keys[i].ID == id {
			entry = &keys[i]
			break
		}
	}
	if entry == nil {
		jsonErr(w, http.StatusNotFound, "key not found")
		return
	}

	// Check if in use.
	usage := keyUsageMap(id)
	if len(usage[id]) > 0 {
		jsonErr(w, http.StatusConflict, "key is in use by: "+strings.Join(usage[id], ", "))
		return
	}

	if err := keystore.DeleteKey(id); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to delete key file: "+err.Error())
		return
	}

	filtered := make([]config.EncryptionKey, 0, len(keys)-1)
	for _, k := range keys {
		if k.ID != id {
			filtered = append(filtered, k)
		}
	}
	if err := config.SaveEncryptionKeys(filtered); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save key metadata")
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionDeleteKey,
		Target: entry.Name,
		Result: audit.ResultOK,
	})

	jsonOK(w, map[string]string{"message": "key deleted"})
}

// HandleKeyUsage returns a map of key ID → list of pool/dataset names using that key.
func HandleKeyUsage(w http.ResponseWriter, r *http.Request) {
	keys, err := config.LoadEncryptionKeys()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load keys")
		return
	}
	result := make(map[string][]string, len(keys))
	for _, k := range keys {
		result[k.ID] = keyUsageMap(k.ID)[k.ID]
	}
	jsonOK(w, result)
}

// keyUsageMap builds a map of {keyID → []entity names} for a single key ID
// by scanning all ZFS datasets' keylocation property.
func keyUsageMap(keyID string) map[string][]string {
	result := map[string][]string{keyID: {}}
	datasets, err := system.ListAllDatasets()
	if err != nil {
		return result
	}
	needle := keyID + ".key"
	for _, ds := range datasets {
		loc := system.GetKeyLocation(ds.Name)
		if strings.HasSuffix(loc, needle) {
			result[keyID] = append(result[keyID], ds.Name)
		}
	}
	return result
}

// HandleLoadPoolKey loads the encryption key for an encrypted pool.
// Body: {"pool": "poolname"}
func HandleLoadPoolKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool string `json:"pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	if req.Pool == "" {
		jsonErr(w, http.StatusBadRequest, "pool is required")
		return
	}

	pool, err := system.GetPoolByName(req.Pool)
	if err != nil || pool == nil {
		jsonErr(w, http.StatusNotFound, "pool not found")
		return
	}

	loc := system.GetKeyLocation(req.Pool)
	if !strings.HasPrefix(loc, "file://") {
		jsonErr(w, http.StatusBadRequest, "pool does not use a file-based key")
		return
	}
	keyPath := strings.TrimPrefix(loc, "file://")
	if err := system.LoadPoolKey(req.Pool, keyPath); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load key: "+err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionLoadKey,
		Target: req.Pool,
		Result: audit.ResultOK,
	})

	pool, _ = system.GetPoolByName(req.Pool)
	jsonOK(w, pool)
}

// HandleUnloadPoolKey unloads the encryption key for a pool (locks it).
// Body: {"pool": "poolname"}
func HandleUnloadPoolKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pool string `json:"pool"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Pool = strings.TrimSpace(req.Pool)
	if req.Pool == "" {
		jsonErr(w, http.StatusBadRequest, "pool is required")
		return
	}

	if err := system.UnloadPoolKey(req.Pool); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to unload key: "+err.Error())
		return
	}

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:   sess.Username,
		Role:   sess.Role,
		Action: audit.ActionUnloadKey,
		Target: req.Pool,
		Result: audit.ResultOK,
	})

	pool, _ := system.GetPoolByName(req.Pool)
	jsonOK(w, pool)
}
