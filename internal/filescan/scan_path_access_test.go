package filescan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectPathTargets_ReturnsPermissionErrorWhenRootNotListable(t *testing.T) {
	tmp := t.TempDir()

	originalProbe := pathScanReadDirProbe
	pathScanReadDirProbe = func(path string) error {
		return os.ErrPermission
	}
	t.Cleanup(func() {
		pathScanReadDirProbe = originalProbe
	})

	_, err := collectPathTargets(tmp, FileScanParams{})
	if err == nil {
		t.Fatalf("expected permission error")
	}
	if !isPermissionDeniedError(err) {
		t.Fatalf("expected permission denied error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "scan path access is denied") {
		t.Fatalf("expected concise access denied message, got: %v", err)
	}
}

func TestCollectPathTargets_EmptyDirectoryReturnsNoError(t *testing.T) {
	tmp := t.TempDir()

	tasks, err := collectPathTargets(tmp, FileScanParams{})
	if err != nil {
		t.Fatalf("collectPathTargets error: %v", err)
	}
	if len(tasks) != 0 {
		t.Fatalf("expected no tasks for empty directory, got %d", len(tasks))
	}
}

func TestCollectPathTargets_FilePathReturnsSingleTask(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "sample.bin")
	if err := os.WriteFile(file, []byte("test"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	tasks, err := collectPathTargets(file, FileScanParams{})
	if err != nil {
		t.Fatalf("collectPathTargets error: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected exactly one task, got %d", len(tasks))
	}
	if tasks[0].Path != file {
		t.Fatalf("expected task path %q, got %q", file, tasks[0].Path)
	}
}
