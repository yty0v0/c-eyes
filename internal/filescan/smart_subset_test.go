package filescan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSmartSubsetBudgetDynamic(t *testing.T) {
	tests := []struct {
		name       string
		total      int
		maxTargets int
		want       int
	}{
		{name: "small set clamps to total", total: 100, maxTargets: 0, want: 100},
		{name: "middle tier", total: 5000, maxTargets: 0, want: 1750},
		{name: "large tier", total: 20000, maxTargets: 0, want: 3000},
		{name: "huge tier", total: 200000, maxTargets: 0, want: 16000},
		{name: "hard cap via max-targets", total: 5000, maxTargets: 50, want: 50},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := smartSubsetBudget(tc.total, tc.maxTargets)
			if got != tc.want {
				t.Fatalf("budget mismatch: total=%d max=%d got=%d want=%d", tc.total, tc.maxTargets, got, tc.want)
			}
		})
	}
}

func TestSelectSmartSubsetHonorsPathScope(t *testing.T) {
	scope := t.TempDir()
	outsideRoot := t.TempDir()
	insideA := filepath.Join(scope, "inside-a.ps1")
	insideB := filepath.Join(scope, "nested", "inside-b.dll")
	outside := filepath.Join(outsideRoot, "outside.exe")

	if err := os.WriteFile(insideA, []byte("a"), 0o644); err != nil {
		t.Fatalf("write insideA: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(insideB), 0o755); err != nil {
		t.Fatalf("mkdir insideB parent: %v", err)
	}
	if err := os.WriteFile(insideB, []byte("b"), 0o644); err != nil {
		t.Fatalf("write insideB: %v", err)
	}
	if err := os.WriteFile(outside, []byte("c"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	tasks := []ScanTask{
		{Path: insideA, Source: SourcePath, Mode: ScanModePath},
		{Path: insideB, Source: SourcePath, Mode: ScanModePath},
		{Path: outside, Source: SourcePath, Mode: ScanModePath},
	}
	selected := selectSmartSubset(tasks, FileScanParams{
		Mode:         ScanModePath,
		Path:         scope,
		SmartEnabled: true,
	})
	if len(selected) == 0 {
		t.Fatal("expected at least one selected target")
	}
	scopeNorm := normalizeComparePath(scope)
	for _, task := range selected {
		if !isPathWithinScope(task.Path, scopeNorm) {
			t.Fatalf("selected task escaped scope: %s (scope=%s)", task.Path, scope)
		}
	}
}

func TestSelectSmartSubsetAppliesMaxTargetsHardCap(t *testing.T) {
	tasks := make([]ScanTask, 0, 100)
	for i := 0; i < 100; i++ {
		tasks = append(tasks, ScanTask{
			Path:   filepath.Join("/tmp", "sample-"+string(rune('a'+(i%26)))+".bin"),
			Source: SourceFull,
			Mode:   ScanModeFull,
		})
	}
	selected := selectSmartSubset(tasks, FileScanParams{
		Mode:         ScanModeFull,
		SmartEnabled: true,
		MaxTargets:   7,
	})
	if len(selected) != 7 {
		t.Fatalf("expected hard cap size 7, got %d", len(selected))
	}
}

func TestScanPathSmartMarksResultAndKeepsPathMode(t *testing.T) {
	tmp := t.TempDir()
	a := filepath.Join(tmp, "a.exe")
	b := filepath.Join(tmp, "b.dll")
	if err := os.WriteFile(a, []byte("a"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, []byte("b"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	results, err := Scan(context.Background(), FileScanParams{
		Mode:         ScanModePath,
		Path:         tmp,
		SmartEnabled: true,
		MaxTargets:   1,
	})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result due max-targets hard cap, got %d", len(results))
	}
	if results[0].SmartEnabled == nil || !*results[0].SmartEnabled {
		t.Fatalf("expected smart_enabled=true, got %+v", results[0].SmartEnabled)
	}
	if results[0].ScanMode == nil || *results[0].ScanMode != ScanModePath {
		t.Fatalf("expected scan_mode=path, got %+v", results[0].ScanMode)
	}
}

func TestIsPathWithinScope_DriveRootWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows-only regression test")
	}

	scope := normalizeComparePath(`D:\`)
	if scope == "" {
		t.Fatal("expected normalized root scope")
	}
	if !isPathWithinScope(`D:\edrsystem\sample.exe`, scope) {
		t.Fatalf("expected path to be within root scope: scope=%q", scope)
	}
	if isPathWithinScope(`E:\edrsystem\sample.exe`, scope) {
		t.Fatalf("expected different drive path to be out of scope: scope=%q", scope)
	}
}
