package scheduledtaskscan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestScanOutputHasNoRiskVerdictFields(t *testing.T) {
	orig := collectScheduledTasksFn
	collectScheduledTasksFn = func(ctx context.Context) ([]ScheduledTaskInfo, error) {
		_ = ctx
		return []ScheduledTaskInfo{{TaskType: strPtr("AT")}}, nil
	}
	defer func() { collectScheduledTasksFn = orig }()

	result, err := Scan(context.Background(), ScheduledTaskScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	rowsAny, ok := decoded["rows"].([]any)
	if !ok || len(rowsAny) == 0 {
		t.Fatalf("expected rows array")
	}
	row, ok := rowsAny[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first row object")
	}
	for _, forbidden := range []string{"riskLevel", "severity", "riskScore", "verdict", "alert"} {
		if _, exists := row[forbidden]; exists {
			t.Fatalf("unexpected risk field in output: %s", forbidden)
		}
	}
}
