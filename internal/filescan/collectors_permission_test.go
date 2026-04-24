package filescan

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectFiles_ReportsWalkPermissionErrorsPerPath(t *testing.T) {
	root := filepath.Join("C:\\", "scan-root")

	originalWalkDirFn := walkDirFn
	walkDirFn = func(path string, fn fs.WalkDirFunc) error {
		if err := fn(filepath.Join(path, "deny-a"), nil, os.ErrPermission); err != nil {
			return err
		}
		if err := fn(filepath.Join(path, "deny-b"), nil, os.ErrPermission); err != nil {
			return err
		}
		return nil
	}
	t.Cleanup(func() {
		walkDirFn = originalWalkDirFn
	})

	var callbackCount int
	var callbackStages []string
	var callbackPaths []string
	var callbackErrs []error

	tasks, err := collectFiles(root, ScanModePath, SourcePath, 0, nil, func(task ScanTask, stage string, taskErr error) {
		callbackCount++
		callbackStages = append(callbackStages, stage)
		callbackPaths = append(callbackPaths, task.Path)
		callbackErrs = append(callbackErrs, taskErr)
	})
	if err != nil {
		t.Fatalf("collectFiles error: %v", err)
	}
	if len(tasks) != 0 {
		t.Fatalf("expected no collected tasks, got %d", len(tasks))
	}
	if callbackCount != 2 {
		t.Fatalf("expected 2 permission callbacks, got %d", callbackCount)
	}

	for i := 0; i < callbackCount; i++ {
		if callbackStages[i] != "collect_targets" {
			t.Fatalf("expected stage collect_targets, got %q", callbackStages[i])
		}
		if callbackPaths[i] == "" {
			t.Fatalf("expected callback path to be populated")
		}
		if !isPermissionDeniedError(callbackErrs[i]) {
			t.Fatalf("expected permission denied error, got %v", callbackErrs[i])
		}
	}
}
