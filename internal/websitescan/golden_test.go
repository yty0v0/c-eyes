package websitescan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertGoldenJSON(t *testing.T, goldenPath string, value any) {
	t.Helper()

	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	data = append(data, '\n')

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, data, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	expected, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}
	expectedText := strings.ReplaceAll(string(expected), "\r\n", "\n")
	actualText := strings.ReplaceAll(string(data), "\r\n", "\n")
	if expectedText != actualText {
		t.Fatalf("golden mismatch: %s\nset UPDATE_GOLDEN=1 to refresh", goldenPath)
	}
}
