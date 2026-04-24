package netscan

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMergeReachabilitySignalsDedupAndScope(t *testing.T) {
	t.Parallel()

	candidates, warnings := mergeReachabilitySignals([]reachabilitySignal{
		{CIDR: "10.50.1.0/24", NextHop: "10.50.1.1", Source: "route_table"},
		{CIDR: "10.50.1.0/24", Source: "active_connections"},
		{CIDR: "0.0.0.0/0", NextHop: "10.0.0.1", Source: "route_table"},
		{CIDR: "192.168.10.0/24", NextHop: "8.8.8.8", Source: "route_table"},
		{CIDR: "2001:db8::/64", Source: "route_table"},
		{CIDR: "not-a-cidr", Source: "route_table"},
	})

	if len(candidates) != 2 {
		t.Fatalf("expected 2 private candidates, got %d (%#v)", len(candidates), candidates)
	}
	if candidates[0].CIDR != "10.50.1.0/24" {
		t.Fatalf("unexpected first candidate: %#v", candidates[0])
	}
	if candidates[0].NextHop != "10.50.1.1" {
		t.Fatalf("expected preserved private nextHop, got %q", candidates[0].NextHop)
	}
	if len(candidates[0].Sources) != 2 {
		t.Fatalf("expected merged sources for candidate, got %#v", candidates[0].Sources)
	}
	if candidates[1].CIDR != "192.168.10.0/24" {
		t.Fatalf("unexpected second candidate: %#v", candidates[1])
	}
	if candidates[1].NextHop != "" {
		t.Fatalf("expected non-private nextHop to be dropped, got %q", candidates[1].NextHop)
	}
	if len(warnings) == 0 {
		t.Fatal("expected filtering warnings for invalid/non-private inputs")
	}
}

func TestBuildVerificationTargetsDeterministic(t *testing.T) {
	t.Parallel()

	targets := buildVerificationTargets(reachabilityCandidate{
		CIDR:    "10.20.30.0/24",
		NextHop: "10.20.30.254",
		Sources: []string{"route_table"},
	})
	want := []string{"10.20.30.254", "10.20.30.1", "10.20.30.2"}
	if len(targets) != len(want) {
		t.Fatalf("unexpected target count: got %v want %v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("unexpected target order/content: got %v want %v", targets, want)
		}
	}
}

func TestVerifyCandidateReachabilityTCPFallback(t *testing.T) {
	originalICMP := reachabilityICMPProbe
	originalTCP := reachabilityTCPPortProbe
	defer func() {
		reachabilityICMPProbe = originalICMP
		reachabilityTCPPortProbe = originalTCP
	}()

	reachabilityICMPProbe = func(target string, mode ScanMode, timeout time.Duration) (bool, error) {
		return false, nil
	}
	reachabilityTCPPortProbe = func(ctx context.Context, target string, port int, timeout time.Duration) bool {
		return target == "10.0.0.2" && port == 3389
	}

	target, method, verified, warnings := verifyCandidateReachability(
		context.Background(),
		[]string{"10.0.0.2"},
		200*time.Millisecond,
		true,
	)
	if !verified {
		t.Fatal("expected candidate to be verified by TCP fallback")
	}
	if target != "10.0.0.2" {
		t.Fatalf("unexpected verification target: %s", target)
	}
	if method != "tcp_connect:3389" {
		t.Fatalf("unexpected verification method: %s", method)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}
}

func TestMergeVerifiedTargetsRespectsMaxTargets(t *testing.T) {
	t.Parallel()

	merged, warnings := mergeVerifiedTargets(
		[]string{"10.0.0.1", "10.0.0.2"},
		[]string{"10.0.0.3", "10.0.0.4"},
		3,
	)
	if len(merged) != 3 {
		t.Fatalf("expected merged target count capped to 3, got %d (%v)", len(merged), merged)
	}
	if len(warnings) == 0 {
		t.Fatal("expected maxTargets warning when verified targets overflow cap")
	}
	if !strings.Contains(strings.ToLower(strings.Join(warnings, " ")), "maxtargets") {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
}
