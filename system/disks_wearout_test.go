package system

import (
	"os"
	"testing"
)

// A SanDisk SD7SB3Q reports its wear as an attribute smartctl doesn't name
// (ID 173, "Unknown_Attribute"), so the wear comes from the ATA Device
// Statistics "Percentage Used Endurance Indicator" (8 on this drive).
func TestParseSMARTATA_DevstatEndurance(t *testing.T) {
	out, err := os.ReadFile("testdata/smartctl-sandisk-sd7sb3q.json")
	if err != nil {
		t.Fatal(err)
	}
	var info DiskInfo
	parseSMARTATA(&info, out)
	if info.WearoutPct == nil || *info.WearoutPct != 8 {
		t.Fatalf("WearoutPct = %v, want 8", info.WearoutPct)
	}
	if !info.SmartOK || info.Serial != "TESTSERIAL0001" {
		t.Fatalf("SmartOK=%v Serial=%q", info.SmartOK, info.Serial)
	}
}

// Without the Device Statistics log (older drives, or smartctl without
// -l devstat) the result is unchanged: no wear value.
func TestParseSMARTATA_NoDevstat(t *testing.T) {
	out := []byte(`{"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
		"ata_smart_attributes":{"table":[{"id":173,"name":"Unknown_Attribute","value":92,"raw":{"value":5}}]}}`)
	var info DiskInfo
	parseSMARTATA(&info, out)
	if info.WearoutPct != nil {
		t.Fatalf("WearoutPct = %d, want nil", *info.WearoutPct)
	}
}

// A recognised vendor attribute keeps priority over the Device Statistics value.
func TestParseSMARTATA_VendorAttributeWins(t *testing.T) {
	out := []byte(`{"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},
		"ata_smart_attributes":{"table":[{"id":177,"name":"Wear_Leveling_Count","value":97,"raw":{"value":40}}]},
		"ata_device_statistics":{"pages":[{"number":7,"table":[{"name":"Percentage Used Endurance Indicator","value":8,"flags":{"valid":true}}]}]}}`)
	var info DiskInfo
	parseSMARTATA(&info, out)
	if info.WearoutPct == nil || *info.WearoutPct != 3 {
		t.Fatalf("WearoutPct = %v, want 3", info.WearoutPct)
	}
}

// The indicator may pass 100 once the rated endurance is used up; an invalid
// entry is ignored.
func TestParseSMARTATA_DevstatClampAndValid(t *testing.T) {
	over := []byte(`{"smart_support":{"available":true},"smart_status":{"passed":true},
		"ata_device_statistics":{"pages":[{"number":7,"table":[{"name":"Percentage Used Endurance Indicator","value":140,"flags":{"valid":true}}]}]}}`)
	var info DiskInfo
	parseSMARTATA(&info, over)
	if info.WearoutPct == nil || *info.WearoutPct != 100 {
		t.Fatalf("WearoutPct = %v, want 100", info.WearoutPct)
	}
	invalid := []byte(`{"smart_support":{"available":true},"smart_status":{"passed":true},
		"ata_device_statistics":{"pages":[{"number":7,"table":[{"name":"Percentage Used Endurance Indicator","value":8,"flags":{"valid":false}}]}]}}`)
	var info2 DiskInfo
	parseSMARTATA(&info2, invalid)
	if info2.WearoutPct != nil {
		t.Fatalf("WearoutPct = %d, want nil for an invalid entry", *info2.WearoutPct)
	}
}
