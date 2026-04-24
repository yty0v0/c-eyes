//go:build windows

package portscan

import (
	"context"
	"testing"
)

type mockWindowsPortCollector struct{}

func (m *mockWindowsPortCollector) Collect() ([]PortInfo, error) {
	return []PortInfo{
		{
			Proto:       strPtr("tcp"),
			Port:        intPtr(3389),
			BindIP:      strPtr("0.0.0.0"),
			PID:         intPtr(1234),
			ProcessName: strPtr("svchost.exe"),
			Status:      intPtr(1),
		},
	}, nil
}

func TestCollectPortsWithMockWindowsProvider(t *testing.T) {
	orig := windowsPortCollectorProvider
	windowsPortCollectorProvider = func() windowsPortCollector { return &mockWindowsPortCollector{} }
	defer func() { windowsPortCollectorProvider = orig }()

	got, err := collectTCPConnectPorts(context.Background())
	if err != nil {
		t.Fatalf("collectTCPConnectPorts error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].ProcessName == nil || *got[0].ProcessName != "svchost.exe" {
		t.Fatalf("unexpected process name: %+v", got[0].ProcessName)
	}
}
