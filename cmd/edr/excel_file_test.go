package main

import (
	"testing"

	"edrsystem/internal/filescan"
)

func TestFileExcelRow_SerializesImports(t *testing.T) {
	path := "/tmp/sample.exe"
	scanResult := filescan.ScanResultSafe
	scanMode := filescan.ScanModeFull
	smartEnabled := true
	dll := "kernel32.dll"

	result := filescan.FileScanResult{
		ScanResult:   &scanResult,
		ScanMode:     &scanMode,
		SmartEnabled: &smartEnabled,
		BasicInfo: &filescan.FileBasicInfo{
			FilePath: &path,
		},
		BinaryInfo: &filescan.FileBinaryInfo{
			ImportedLibraries: []filescan.FileImport{
				{
					Dll:       &dll,
					Functions: []string{"CreateFileW"},
				},
			},
		},
	}

	row := fileExcelRow(result)
	idx := headerIndex("binary_info.imported_libraries")
	if idx < 0 || idx >= len(row) {
		t.Fatalf("invalid header index for imported_libraries: %d", idx)
	}
	val, ok := row[idx].(string)
	if !ok {
		t.Fatalf("expected string cell, got %T", row[idx])
	}
	expected := `[{"dll":"kernel32.dll","functions":["CreateFileW"]}]`
	if val != expected {
		t.Fatalf("unexpected import cell: %s", val)
	}

	smartIdx := headerIndex("smart_enabled")
	if smartIdx < 0 || smartIdx >= len(row) {
		t.Fatalf("invalid header index for smart_enabled: %d", smartIdx)
	}
	if got, ok := row[smartIdx].(bool); !ok || !got {
		t.Fatalf("expected smart_enabled=true, got %T(%v)", row[smartIdx], row[smartIdx])
	}
}

func TestFileExcelRow_NullHandling(t *testing.T) {
	result := filescan.FileScanResult{}
	row := fileExcelRow(result)

	idx := headerIndex("basic_info.file_path")
	if idx < 0 || idx >= len(row) {
		t.Fatalf("invalid header index for file_path: %d", idx)
	}
	if row[idx] != "" {
		t.Fatalf("expected empty cell for missing file_path, got %v", row[idx])
	}

	idx = headerIndex("hashes.sha256")
	if idx < 0 || idx >= len(row) {
		t.Fatalf("invalid header index for hashes.sha256: %d", idx)
	}
	if row[idx] != "" {
		t.Fatalf("expected empty cell for missing sha256, got %v", row[idx])
	}
}

func headerIndex(name string) int {
	for i, header := range fileScanHeaders {
		if header == name {
			return i
		}
	}
	return -1
}
