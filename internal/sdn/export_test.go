package sdn

import (
	"errors"
	"testing"
	"time"

	"zfsnas/internal/backup"
)

const testPW = "correct horse battery"

func TestExportRoundTrip(t *testing.T) {
	data, err := Export(ownerSample(), ExportFile{ZNASVersion: "6.10.28", Hostname: "znas40", CreatedAt: time.Now()}, testPW)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Import(data, testPW)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != "znas-sdn" || f.Schema != 1 || f.Hostname != "znas40" || len(f.Config.Rules) != 2 {
		t.Fatalf("round trip: %+v", f)
	}
}

func TestExportShortPassword(t *testing.T) {
	if _, err := Export(ownerSample(), ExportFile{}, "short"); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestImportWrongPassword(t *testing.T) {
	data, _ := Export(ownerSample(), ExportFile{}, testPW)
	if _, err := Import(data, "wrong password!!"); !errors.Is(err, backup.ErrBadPassword) {
		t.Fatalf("err = %v", err)
	}
}

func TestImportNotSDN(t *testing.T) {
	data, _ := backup.Seal(testPW, []byte(`{"kind":"something-else"}`))
	if _, err := Import(data, testPW); !errors.Is(err, ErrNotSDNExport) {
		t.Fatalf("err = %v", err)
	}
}

func TestRemapDevices(t *testing.T) {
	c := ownerSample()
	c.Settings.MgmtInterface = "enp1s0"
	got := RemapDevices(c, map[string]string{"enp1s0": "eno1", "enp2s0": "eno2"})
	if got.Interfaces[0].Device != "eno1" || got.Settings.MgmtInterface != "eno1" {
		t.Fatalf("physical/mgmt not remapped: %+v", got.Interfaces[0])
	}
	if got.Interfaces[1].Parent != "eno2" || got.Interfaces[1].Device != "eno2-v400" {
		t.Fatalf("vlan not remapped: %+v", got.Interfaces[1])
	}
	if c.Interfaces[0].Device != "enp1s0" {
		t.Fatal("RemapDevices modified its input")
	}
}

func TestDevicesNeeded(t *testing.T) {
	got := DevicesNeeded(ownerSample())
	if len(got) != 2 || got[0] != "enp1s0" || got[1] != "enp2s0" {
		t.Fatalf("got %v", got)
	}
}
