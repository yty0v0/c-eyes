package usergroupscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputIncludesTotalAndRows(t *testing.T) {
	orig := collectUserGroupsFn
	collectUserGroupsFn = func(ctx context.Context) ([]UserGroupInfo, error) {
		_ = ctx
		return []UserGroupInfo{
			{
				Name: strPtr("developers"),
				GID:  int64Ptr(1000),
			},
		}, nil
	}
	defer func() { collectUserGroupsFn = orig }()

	result, err := Scan(context.Background(), UserGroupScanParams{})
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
		t.Fatalf("expected hostTagList default to []")
	}
	if result.Rows[0].Members == nil {
		t.Fatalf("expected members default to []")
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
