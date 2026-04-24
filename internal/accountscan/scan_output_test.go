package accountscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalAndRows(t *testing.T) {
	orig := collectAccountsFn
	collectAccountsFn = func(ctx context.Context) ([]AccountInfo, error) {
		_ = ctx
		return []AccountInfo{
			{
				Name: strPtr("alice"),
				UID:  int64Ptr(1000),
				GID:  int64Ptr(1000),
			},
		}, nil
	}
	defer func() { collectAccountsFn = orig }()

	result, err := Scan(context.Background(), AccountScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(result.Rows))
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
