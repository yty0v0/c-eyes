package environmentscan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanOutputHasNoRiskVerdictFields(t *testing.T) {
	orig := collectEnvironmentFn
	collectEnvironmentFn = func(ctx context.Context) ([]EnvironmentInfo, error) {
		_ = ctx
		return []EnvironmentInfo{{
			Key:    strPtr("PATH"),
			Value:  strPtr("/usr/bin"),
			SysEnv: boolPtr(true),
		}}, nil
	}
	defer func() { collectEnvironmentFn = orig }()

	result, err := Scan(context.Background(), EnvironmentScanParams{})
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

func TestCollectorsDoNotImportOSExec(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve current file path")
	}

	patterns := []string{
		filepath.Join(filepath.Dir(currentFile), "scan_*.go"),
		filepath.FromSlash("internal/environmentscan/scan_*.go"),
		"scan_*.go",
	}
	matches := make([]string, 0)
	for _, pattern := range patterns {
		found, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob scan files (%s): %v", pattern, err)
		}
		matches = append(matches, found...)
	}
	if len(matches) == 0 {
		t.Fatalf("expected scan implementation files")
	}
	for _, name := range matches {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(data), `"os/exec"`) {
			t.Fatalf("file %s imports os/exec, expected in-process collection only", name)
		}
	}
}
