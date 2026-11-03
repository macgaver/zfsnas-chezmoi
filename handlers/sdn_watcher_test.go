package handlers

import (
	"strings"
	"testing"
	"time"

	"zfsnas/system"
)

func TestSDNGatewayAlerts(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	st := system.GWStateFile{Active: "gwisp002", Gateways: []system.GWStatus{{ID: "gwisp002", Name: "ISP2"}}, Events: []system.GWEvent{
		{At: t0, Kind: "down", ID: "gwisp001", Name: "ISP1"},
		{At: t0.Add(time.Second), Kind: "down", ID: "gwisp001", Name: "ISP1"},
		{At: t0.Add(2 * time.Second), Kind: "failover", ID: "gwisp002", Name: "ISP2", Active: "gwisp002"},
	}}
	got, last := sdnGatewayAlerts(st, t0)
	if len(got) != 2 || !last.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("got %d alerts, last %v", len(got), last)
	}
	if !strings.Contains(got[0].title, "ISP1") || !strings.Contains(got[0].title, "down") {
		t.Fatalf("down title %q", got[0].title)
	}
	if !strings.Contains(got[1].body, "ISP2") {
		t.Fatalf("failover body %q", got[1].body)
	}
	if again, _ := sdnGatewayAlerts(st, last); len(again) != 0 {
		t.Fatalf("resent %d", len(again))
	}
}
