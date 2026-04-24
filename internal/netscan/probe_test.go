package netscan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestModeSourceUsesOverride(t *testing.T) {
	t.Parallel()

	got := modeSource(ModeTCPSYN, modeResult{Source: "tcp_connect"})
	if got != "tcp_connect" {
		t.Fatalf("expected override source tcp_connect, got %q", got)
	}
}

func TestModeSourceFallsBackToCapability(t *testing.T) {
	t.Parallel()

	got := modeSource(ModeUDP, modeResult{})
	if got != modeCapabilities[ModeUDP].Source {
		t.Fatalf("expected capability source %q, got %q", modeCapabilities[ModeUDP].Source, got)
	}
}

func TestProbeARPFallbackAlwaysReportsCompatibilityWarningForPrivateIPv4(t *testing.T) {
	t.Parallel()

	result := probeARPFallback(context.Background(), "10.255.255.1", 1*time.Millisecond)
	if !strings.Contains(result.Warn, "ARP-compatible fallback") {
		t.Fatalf("expected compatibility fallback warning, got %q", result.Warn)
	}
}
