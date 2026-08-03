package alerts

import (
	"testing"
	"time"
)

// AnyTargetWants must consult the full matchesEvent table. A previous copy of
// this logic in handlers only knew smart_error/wearout_exceeded, which silently
// disabled the scrub-errors and security-updates polling gates.
func TestAnyTargetWantsCoversAllKeys(t *testing.T) {
	keys := []EventKey{
		EventPoolDegraded, EventSmartError, EventWearoutExceeded,
		EventFailedLogin, EventSecurityUpdates, EventScrubErrors,
		EventSnapshotFailure, EventReplicationFailure, EventUserCreated,
		EventShareCreated, EventPoolActions, EventVMStartFailure,
		EventVMUnexpectedStop, EventVMCreatedDeleted, EventVMSnapshotFailure,
		EventVMBackupFailure, EventVMDiskFull, EventVMHostSaturation,
		EventComposeUpdateFailure, EventInterlinkUnreachable,
		EventUPSPowerChanged,
	}
	all := EventConfig{
		PoolDegraded: true, SmartError: true, WearoutExceeded: true,
		FailedLoginAlert: true, SecurityUpdates: true, ScrubErrors: true,
		SnapshotFailure: true, ReplicationFailure: true, UserCreatedDeleted: true,
		ShareCreatedDeleted: true, PoolActions: true, VMStartFailure: true,
		VMUnexpectedStop: true, VMCreatedDeleted: true, VMSnapshotFailure: true,
		VMBackupFailure: true, VMDiskFull: true, VMHostSaturation: true,
		ComposeUpdateFailure: true, InterlinkUnreachable: true,
		UPSPowerChanged: true,
	}
	cfg := &AlertConfig{WebSocket: WebSocketTarget{Enabled: true, Events: all}}
	for _, k := range keys {
		if !AnyTargetWants(cfg, k) {
			t.Errorf("AnyTargetWants(%q) = false with every event enabled — matchesEvent is missing a case", k)
		}
	}

	none := &AlertConfig{WebSocket: WebSocketTarget{Enabled: true}}
	for _, k := range keys {
		if AnyTargetWants(none, k) {
			t.Errorf("AnyTargetWants(%q) = true with every event disabled", k)
		}
	}

	// A disabled target must not count, even with the event subscribed.
	disabled := &AlertConfig{WebSocket: WebSocketTarget{Enabled: false, Events: all}}
	if AnyTargetWants(disabled, EventInterlinkUnreachable) {
		t.Error("AnyTargetWants counted a disabled target")
	}
}

// SendSync is what the UPS pre-shutdown notice uses: unlike Send it must not
// return until delivery is settled, and it must never outlast its timeout.
func TestSendSyncWithNoSubscribersIsInstantAndNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ZFSNAS_CONFIG_DIR", dir)
	start := time.Now()
	attempted, delivered, err := SendSync(EventUPSPowerChanged, "s", "e", "d", 5*time.Second)
	if err != nil {
		t.Fatalf("no configured targets should not be an error: %v", err)
	}
	if attempted != 0 || delivered != 0 {
		t.Errorf("attempted=%d delivered=%d, want 0/0", attempted, delivered)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("took %s with nothing configured", el)
	}
}
