package portscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalAndRows(t *testing.T) {
	origConnect := collectTCPConnectPortsFn
	origSyn := collectTCPSYNPortsFn
	collectTCPConnectPortsFn = func(ctx context.Context) ([]PortInfo, error) {
		_ = ctx
		return []PortInfo{
			{
				Proto:  strPtr("tcp"),
				Port:   intPtr(80),
				BindIP: strPtr("0.0.0.0"),
			},
		}, nil
	}
	collectTCPSYNPortsFn = collectTCPConnectPortsFn
	defer func() {
		collectTCPConnectPortsFn = origConnect
		collectTCPSYNPortsFn = origSyn
	}()

	result, err := Scan(context.Background(), PortScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected rows=1, got %d", len(result.Rows))
	}
	if result.Rows[0].HostTagList == nil {
		t.Fatalf("expected hostTagList default []")
	}
	if result.Rows[0].ExternalIPList == nil {
		t.Fatalf("expected externalIpList default []")
	}
	if result.Rows[0].InternalIPList == nil {
		t.Fatalf("expected internalIpList default []")
	}
	if result.Rows[0].Status == nil {
		t.Fatalf("expected status default")
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if _, ok := decoded["total"]; !ok {
		t.Fatalf("missing total key")
	}
	if _, ok := decoded["rows"]; !ok {
		t.Fatalf("missing rows key")
	}
}

func TestScanModeDefaultsToTCPConnect(t *testing.T) {
	origConnect := collectTCPConnectPortsFn
	origSyn := collectTCPSYNPortsFn
	connectCalled := 0
	synCalled := 0
	collectTCPConnectPortsFn = func(ctx context.Context) ([]PortInfo, error) {
		_ = ctx
		connectCalled++
		return []PortInfo{}, nil
	}
	collectTCPSYNPortsFn = func(ctx context.Context) ([]PortInfo, error) {
		_ = ctx
		synCalled++
		return []PortInfo{}, nil
	}
	defer func() {
		collectTCPConnectPortsFn = origConnect
		collectTCPSYNPortsFn = origSyn
	}()

	if _, err := Scan(context.Background(), PortScanParams{}); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if connectCalled != 1 || synCalled != 0 {
		t.Fatalf("expected connect mode by default, connect=%d syn=%d", connectCalled, synCalled)
	}
}

func TestScanModeTCPSYN(t *testing.T) {
	origConnect := collectTCPConnectPortsFn
	origSyn := collectTCPSYNPortsFn
	connectCalled := 0
	synCalled := 0
	collectTCPConnectPortsFn = func(ctx context.Context) ([]PortInfo, error) {
		_ = ctx
		connectCalled++
		return []PortInfo{}, nil
	}
	collectTCPSYNPortsFn = func(ctx context.Context) ([]PortInfo, error) {
		_ = ctx
		synCalled++
		return []PortInfo{}, nil
	}
	defer func() {
		collectTCPConnectPortsFn = origConnect
		collectTCPSYNPortsFn = origSyn
	}()

	if _, err := Scan(context.Background(), PortScanParams{Mode: ScanModeTCPSYN}); err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if connectCalled != 0 || synCalled != 1 {
		t.Fatalf("expected syn mode, connect=%d syn=%d", connectCalled, synCalled)
	}
}
