package capacityrrd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withWriteEvery(t *testing.T, d time.Duration) {
	old := WriteEvery
	WriteEvery = d
	t.Cleanup(func() { WriteEvery = old })
}

func TestStorage_GzipRoundTripAndMigration(t *testing.T) {
	withWriteEvery(t, 0)
	dir := t.TempDir()
	path := filepath.Join(dir, "capacity.rrd.json")
	now := time.Now()

	// an older build's plain file
	old, _ := Open(path)
	old.Record("pool:tank:used", 42, now)
	b, _ := json.Marshal(&old.data)
	old.Close()
	if err := os.WriteFile(path, b, 0640); err != nil {
		t.Fatal(err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Query(0, "pool:tank:used"); len(got) != 1 || got[0].Avg != 42 {
		t.Fatalf("plain file not read: %+v", got)
	}
	if err := db.Flush(); err != nil { // dirty after a migration: writes .gz
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("plain file still there after the compressed write")
	}
	if _, err := os.Stat(path + ".gz"); err != nil {
		t.Fatal("no compressed file")
	}
	db.Record("pool:tank:used", 43, now.Add(5*time.Minute))
	if err := db.FlushNow(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	again, _ := Open(path)
	if got := again.Query(0, "pool:tank:used"); len(got) != 2 || got[1].Avg != 43 {
		t.Fatalf("compressed file not read back: %+v", got)
	}
	again.Close()
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestStorage_NewerFileWins(t *testing.T) {
	withWriteEvery(t, 0)
	dir := t.TempDir()
	path := filepath.Join(dir, "x.rrd.json")
	now := time.Now()
	db, _ := Open(path)
	db.Record("k", 1, now)
	_ = db.FlushNow()
	db.Close()
	// a restored backup puts a plain file back, newer than the .gz
	other, _ := Open(filepath.Join(dir, "other.rrd.json"))
	other.Record("k", 7, now)
	b, _ := json.Marshal(&other.data)
	other.Close()
	_ = os.WriteFile(path, b, 0640)
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(path, future, future)
	got, _ := Open(path)
	if q := got.Query(0, "k"); len(q) != 1 || q[0].Avg != 7 {
		t.Fatalf("the newer (restored) file should win: %+v", q)
	}
	got.Close()
}

func TestStorage_ThrottleDirtyAndClose(t *testing.T) {
	withWriteEvery(t, time.Hour)
	registry.Lock() // only this test's DB for FlushAll
	saved := registry.dbs
	registry.dbs = map[*DB]bool{}
	registry.Unlock()
	t.Cleanup(func() { registry.Lock(); registry.dbs = saved; registry.Unlock() })
	dir := t.TempDir()
	path := filepath.Join(dir, "y.rrd.json")
	db, _ := Open(path)
	if err := db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".gz"); !os.IsNotExist(err) {
		t.Fatal("nothing to save, yet a file was written")
	}
	db.Record("k", 1, time.Now())
	_ = db.Flush() // within WriteEvery: waits
	if _, err := os.Stat(path + ".gz"); !os.IsNotExist(err) {
		t.Fatal("written before WriteEvery")
	}
	FlushAll() // shutdown: writes now
	if _, err := os.Stat(path + ".gz"); err != nil {
		t.Fatal("FlushAll did not write")
	}
	db.Record("k", 2, time.Now().Add(5*time.Minute))
	db.Close()
	os.Remove(path + ".gz") // the instance was deleted
	FlushAll()
	_ = db.FlushNow()
	if _, err := os.Stat(path + ".gz"); !os.IsNotExist(err) {
		t.Fatal("a closed DB wrote its deleted file back")
	}
}
