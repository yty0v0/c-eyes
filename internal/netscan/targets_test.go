package netscan

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSelectPrimaryCandidatePrefersDetectedIPv4(t *testing.T) {
	t.Parallel()

	candidates := []interfaceCandidate{
		{
			Index:        10,
			PrivateIPv4s: []net.IP{net.ParseIP("172.23.112.1")},
		},
		{
			Index:        20,
			PrivateIPv4s: []net.IP{net.ParseIP("192.168.1.9")},
		},
	}

	got := selectPrimaryCandidate(candidates, net.ParseIP("192.168.1.9"), nil, false)
	if got == nil {
		t.Fatal("expected a selected candidate, got nil")
	}
	if got.Index != 20 {
		t.Fatalf("expected interface index 20, got %d", got.Index)
	}
}

func TestSelectPrimaryCandidateFallsBackToFirstPrivateIPv4(t *testing.T) {
	t.Parallel()

	candidates := []interfaceCandidate{
		{
			Index:        2,
			PrivateIPv4s: []net.IP{net.ParseIP("10.0.0.9")},
		},
		{
			Index:        3,
			PrivateIPv4s: []net.IP{net.ParseIP("192.168.1.9")},
		},
	}

	got := selectPrimaryCandidate(candidates, nil, nil, false)
	if got == nil {
		t.Fatal("expected a selected candidate, got nil")
	}
	if got.Index != 2 {
		t.Fatalf("expected interface index 2, got %d", got.Index)
	}
}

func TestBuildDefaultTargetsForInterfaceUsesSingleIPv4CSegment(t *testing.T) {
	t.Parallel()

	candidate := interfaceCandidate{
		PrivateIPv4s: []net.IP{
			net.ParseIP("192.168.56.1"),
			net.ParseIP("10.0.0.8"),
		},
	}

	targets := buildDefaultTargetsForInterface(candidate, false, nil, nil)
	if len(targets) != 254 {
		t.Fatalf("expected 254 targets for one C-segment, got %d", len(targets))
	}
	if targets[0] != "192.168.56.1" {
		t.Fatalf("expected first target 192.168.56.1, got %s", targets[0])
	}
	if targets[len(targets)-1] != "192.168.56.254" {
		t.Fatalf("expected last target 192.168.56.254, got %s", targets[len(targets)-1])
	}
	for _, target := range targets {
		if target == "10.0.0.1" {
			t.Fatalf("unexpected secondary subnet target included: %s", target)
		}
	}
}

func TestCollectTargetTokensSkipsBOMComment(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "\uFEFF# comment line with BOM\n127.0.0.1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	tokens, err := collectTargetTokens("", path)
	if err != nil {
		t.Fatalf("collectTargetTokens error: %v", err)
	}
	want := []string{"127.0.0.1"}
	if !reflect.DeepEqual(tokens, want) {
		t.Fatalf("unexpected tokens: got %v want %v", tokens, want)
	}
}
