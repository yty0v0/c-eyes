package kernelscan

import (
	"context"
	"encoding/json"
	"testing"

	"edrsystem/internal/processscan"
)

type stubProvider struct {
	rows []KernelModuleInfo
	err  error
}

func (s stubProvider) Collect(ctx context.Context) ([]KernelModuleInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.rows, s.err
}

func TestScanOutputIncludesTotalAndRows(t *testing.T) {
	orig := newKernelScanProvider
	newKernelScanProvider = func() KernelScanProvider {
		return stubProvider{
			rows: []KernelModuleInfo{
				{
					ModuleName: strPtr("tcpip"),
				},
			},
		}
	}
	defer func() { newKernelScanProvider = orig }()

	result, err := Scan(context.Background(), KernelScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
	}
	if result.Rows[0].HostTagList == nil {
		t.Fatalf("expected hostTagList default []")
	}
	if result.Rows[0].ExternalIPs == nil {
		t.Fatalf("expected externalIps default []")
	}
	if result.Rows[0].InternalIPs == nil {
		t.Fatalf("expected internalIps default []")
	}
	if result.Rows[0].Depends == nil {
		t.Fatalf("expected depends default []")
	}
	if result.Rows[0].Holders == nil {
		t.Fatalf("expected holders default []")
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

func TestApplyHostPreservesAllNICIPs(t *testing.T) {
	row := KernelModuleInfo{}
	host := processscan.HostInfo{
		Hostname:    "node-a",
		DisplayIP:   strPtr("203.0.113.10"),
		ExternalIPs: []string{"203.0.113.10", "198.51.100.20"},
		InternalIPs: []string{"10.0.0.2", "192.168.1.8"},
		BizGroupID:  int64Ptr(39),
	}

	applyHost(&row, host)
	normalizeDefaults(&row)

	if row.DisplayIP == nil || *row.DisplayIP != "203.0.113.10" {
		t.Fatalf("unexpected displayIp: %+v", row.DisplayIP)
	}
	if len(row.ExternalIPs) != 2 || row.ExternalIPs[0] != "203.0.113.10" || row.ExternalIPs[1] != "198.51.100.20" {
		t.Fatalf("unexpected externalIps: %+v", row.ExternalIPs)
	}
	if len(row.InternalIPs) != 2 || row.InternalIPs[0] != "10.0.0.2" || row.InternalIPs[1] != "192.168.1.8" {
		t.Fatalf("unexpected internalIps: %+v", row.InternalIPs)
	}
	if row.BizGroupID == nil || *row.BizGroupID != 39 {
		t.Fatalf("unexpected bizGroupId: %+v", row.BizGroupID)
	}
}
