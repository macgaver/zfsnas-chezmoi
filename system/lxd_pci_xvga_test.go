package system

import (
	"strings"
	"testing"
)

// TestBuildPCIQEMUArgXVGAOn — production-incident regression test. Picking
// "On" in the x-vga dropdown (frontend stores "1") used to emit
//
//	-device vfio-pci,host=0000:00:02.0,x-vga=1
//
// and QEMU 10.x rejected with "Parameter 'x-vga' expects 'on' or 'off'",
// preventing iGPU passthrough from starting. After v6.5.19 the emitter
// must convert the dropdown's "1"/"0" form into QEMU's required "on"/"off"
// for the boolean-typed properties (x-vga, aer) while leaving rombar
// numeric.
func TestBuildPCIQEMUArgXVGAOn(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{
		Address: "0000:00:02.0",
		XVGA:    "1",
	})
	if !strings.Contains(got, "x-vga=on") {
		t.Errorf("expected x-vga=on, got: %q", got)
	}
	if strings.Contains(got, "x-vga=1") {
		t.Errorf("emitter still produces x-vga=1 (QEMU rejects this): %q", got)
	}
}

// TestBuildPCIQEMUArgAEROn — same regression for the AER property
// (vfio-pci.aer is also a QEMU bool).
func TestBuildPCIQEMUArgAEROn(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{Address: "0000:01:00.0", AER: "1"})
	if !strings.Contains(got, "aer=on") {
		t.Errorf("expected aer=on, got: %q", got)
	}
}

// TestBuildPCIQEMUArgRomBarStaysNumeric — rombar is a uint32 in QEMU's
// device tree, not a bool. We must pass through 0/1 verbatim; rewriting it
// to on/off here would be a different regression.
func TestBuildPCIQEMUArgRomBarStaysNumeric(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{Address: "0000:01:00.0", ROMBar: "1"})
	if !strings.Contains(got, "rombar=1") {
		t.Errorf("rombar must stay numeric (1), got: %q", got)
	}
	got = buildPCIQEMUArg(LXDPCIDevice{Address: "0000:01:00.0", ROMBar: "0"})
	if !strings.Contains(got, "rombar=0") {
		t.Errorf("rombar must stay numeric (0), got: %q", got)
	}
}

// TestBuildPCIQEMUArgAllOff — picking "Off" must produce QEMU's "off",
// not "0", for x-vga and aer. This matters because some PCI devices need
// x-vga=off to be explicit (vs inherited default).
func TestBuildPCIQEMUArgAllOff(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{
		Address: "0000:00:02.0",
		XVGA:    "0",
		AER:     "0",
	})
	if !strings.Contains(got, "x-vga=off") {
		t.Errorf("expected x-vga=off, got: %q", got)
	}
	if !strings.Contains(got, "aer=off") {
		t.Errorf("expected aer=off, got: %q", got)
	}
}

// TestBuildPCIQEMUArgNoOptions — no extra options means no -device line at
// all (Incus' default vfio-pci device suffices). Returning "" lets
// applyPCIRawQEMU skip emission cleanly.
func TestBuildPCIQEMUArgNoOptions(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{Address: "0000:00:02.0"})
	if got != "" {
		t.Errorf("expected empty (no override needed), got: %q", got)
	}
}

// TestPciBoolToken covers each accepted shape on the way IN to QEMU.
func TestPciBoolToken(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"1":     "on",
		"on":    "on",
		"ON":    "on", // case-insensitive
		"True":  "on",
		"yes":   "on",
		"0":     "off",
		"off":   "off",
		"False": "off",
		"no":    "off",
		// Pass-through: anything we don't recognize reaches QEMU verbatim
		// so an advanced operator isn't blocked by our normalization.
		"some-future-flag": "some-future-flag",
	}
	for in, want := range cases {
		if got := pciBoolToken(in); got != want {
			t.Errorf("pciBoolToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestBuildPCIQEMUArgUsesSetDeviceForm — when the caller provides a
// DeviceName (the normal path; ZNAS' Incus model names PCI devices
// "pci0", "pci1", etc.), the emitter MUST produce the
// `-set device.dev-incus_<DeviceName>.<prop>=<val>` shape, never a fresh
// `-device vfio-pci,host=<addr>` line. Production regression on
// a test host (May 2026, iGPU passthrough): the legacy
// form added a second `-device vfio-pci` for the host BDF and QEMU
// failed VM start with "vfio 0000:00:02.0: device is already attached"
// because Incus' own `[device "dev-incus_pci0"]` had already claimed
// the same host device.
func TestBuildPCIQEMUArgUsesSetDeviceForm(t *testing.T) {
	got := buildPCIQEMUArg(LXDPCIDevice{
		DeviceName: "pci0",
		Address:    "0000:00:02.0",
		XVGA:       "1",
		ROMBar:     "1",
		AER:        "0",
	})
	wants := []string{
		"-set device.dev-incus_pci0.rombar=1",
		"-set device.dev-incus_pci0.x-vga=on",
		"-set device.dev-incus_pci0.aer=off",
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in: %q", w, got)
		}
	}
	if strings.Contains(got, "-device vfio-pci") {
		t.Errorf("must NOT emit a second -device vfio-pci line — Incus already does that: %q", got)
	}
}

// TestParsePCIQEMUArgsBothForms verifies that the read path decodes both
// the new `-set device.<id>.<prop>=<val>` form and the legacy
// `-device vfio-pci,host=<addr>,<prop>=<val>` form, populating the same
// result map under different keys so the GET-instance-config path can
// look up by either DeviceName or PCI address.
func TestParsePCIQEMUArgsBothForms(t *testing.T) {
	raw := strings.Join([]string{
		// New form.
		"-set device.dev-incus_pci0.x-vga=on",
		"-set device.dev-incus_pci0.rombar=1",
		// Legacy form on a different device.
		"-device vfio-pci,host=0000:01:00.0,x-vga=on,aer=off",
	}, " ")
	out := parsePCIQEMUArgs(raw)

	newOpts, ok := out["dev-incus_pci0"]
	if !ok {
		t.Fatalf("missing key dev-incus_pci0 in parsed output: %v", out)
	}
	if newOpts["x-vga"] != "on" || newOpts["rombar"] != "1" {
		t.Errorf("dev-incus_pci0 opts wrong: %v", newOpts)
	}

	legacyOpts, ok := out["0000:01:00.0"]
	if !ok {
		t.Fatalf("missing legacy address key in parsed output: %v", out)
	}
	if legacyOpts["x-vga"] != "on" || legacyOpts["aer"] != "off" {
		t.Errorf("legacy 0000:01:00.0 opts wrong: %v", legacyOpts)
	}
}

// TestPciBoolFromQEMU covers the read path. raw.qemu round-trips back to
// the dropdown's "1"/"0" form so opening the Edit modal on a VM with a
// previously-set x-vga / aer keeps the right option highlighted.
func TestPciBoolFromQEMU(t *testing.T) {
	cases := map[string]string{
		"":       "",
		"on":     "1",
		"ON":     "1", // case-insensitive
		"true":   "1",
		"yes":    "1",
		"1":      "1",
		"off":    "0",
		"false":  "0",
		"no":     "0",
		"0":      "0",
		"foobar": "foobar", // unknown stays as-is
	}
	for in, want := range cases {
		if got := pciBoolFromQEMU(in); got != want {
			t.Errorf("pciBoolFromQEMU(%q) = %q, want %q", in, got, want)
		}
	}
}
