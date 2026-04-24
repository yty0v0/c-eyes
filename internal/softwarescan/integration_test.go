package softwarescan

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCollectorsDoNotImportOSExec(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("failed to resolve current file path")
	}

	patterns := []string{
		filepath.Join(filepath.Dir(currentFile), "scan_*.go"),
		filepath.FromSlash("internal/softwarescan/scan_*.go"),
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
