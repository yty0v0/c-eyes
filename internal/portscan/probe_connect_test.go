package portscan

import (
	"context"
	"net"
	"testing"
)

func TestApplyTCPConnectProbeReachableSetsStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	rows := []PortInfo{
		{
			Proto:  strPtr("tcp"),
			BindIP: strPtr("127.0.0.1"),
			Port:   intPtr(port),
			Status: intPtr(-1),
		},
	}

	got := applyTCPConnectProbe(context.Background(), rows)
	if len(got) != 1 || got[0].Status == nil {
		t.Fatalf("unexpected probe result: %+v", got)
	}
	if *got[0].Status != 0 {
		t.Fatalf("expected status=0 for reachable loopback, got %d", *got[0].Status)
	}
}

func TestApplyTCPConnectProbeUnreachableKeepsExistingStatus(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	rows := []PortInfo{
		{
			Proto:  strPtr("tcp"),
			BindIP: strPtr("127.0.0.1"),
			Port:   intPtr(port),
			Status: intPtr(0),
		},
	}

	got := applyTCPConnectProbe(context.Background(), rows)
	if len(got) != 1 || got[0].Status == nil {
		t.Fatalf("unexpected probe result: %+v", got)
	}
	if *got[0].Status != 0 {
		t.Fatalf("expected existing status to be preserved, got %d", *got[0].Status)
	}
}

func TestProbeTargetsForWildcards(t *testing.T) {
	if targets := probeTargets("0.0.0.0"); len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("unexpected targets for ipv4 wildcard: %+v", targets)
	}
	targets := probeTargets("::")
	if len(targets) != 2 || targets[0] != "::1" || targets[1] != "127.0.0.1" {
		t.Fatalf("unexpected targets for ipv6 wildcard: %+v", targets)
	}
}
