package startupscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalAndRows(t *testing.T) {
	orig := collectStartupItemsFn
	collectStartupItemsFn = func(ctx context.Context) ([]StartupInfo, error) {
		_ = ctx
		return []StartupInfo{
			{
				Name: strPtr("sshd"),
			},
		}, nil
	}
	defer func() { collectStartupItemsFn = orig }()

	result, err := Scan(context.Background(), StartupScanParams{})
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
	if result.Rows[0].ExternalIPList == nil {
		t.Fatalf("expected externalIpList default []")
	}
	if result.Rows[0].InternalIPList == nil {
		t.Fatalf("expected internalIpList default []")
	}
	if result.Rows[0].Xinetd == nil {
		t.Fatalf("expected xinetd default")
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
