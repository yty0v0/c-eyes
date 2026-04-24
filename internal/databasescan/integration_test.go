package databasescan

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
	orig := collectDatabaseRecordsFn
	collectDatabaseRecordsFn = func(ctx context.Context) ([]DatabaseRecord, error) {
		_ = ctx
		return []DatabaseRecord{{
			Name: strPtr("MySQL"),
			Port: intPtr(3306),
		}}, nil
	}
	defer func() { collectDatabaseRecordsFn = orig }()

	result, err := Scan(context.Background(), DatabaseScanParams{})
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
		filepath.FromSlash("internal/databasescan/scan_*.go"),
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

func TestLinuxWindowsFixtureConsistency(t *testing.T) {
	linuxFixture := DatabaseRecord{
		Name:           strPtr("MySQL"),
		Version:        strPtr("8.0"),
		Port:           intPtr(3306),
		ProtoType:      strPtr("tcp"),
		ConfPath:       strPtr("/etc/mysql/mysql.cnf"),
		LogPath:        strPtr("/var/log/mysql/error.log"),
		DataDir:        strPtr("/var/lib/mysql"),
		ExternalIPList: []string{"8.8.8.8"},
		InternalIPList: []string{"192.168.1.8"},
	}
	windowsFixture := DatabaseRecord{
		Name:           strPtr("MySQL"),
		Version:        strPtr("8.0"),
		Port:           intPtr(3306),
		ProtoType:      strPtr("tcp"),
		ConfPath:       strPtr(`C:\ProgramData\MySQL\my.ini`),
		LogPath:        strPtr(`C:\ProgramData\MySQL\Logs\error.log`),
		DataDir:        strPtr(`C:\ProgramData\MySQL\Data`),
		ExternalIPList: []string{"8.8.8.8"},
		InternalIPList: []string{"192.168.1.8"},
	}

	normalize := func(row DatabaseRecord) (name string, version string, port int, proto string) {
		if row.Name != nil {
			name = *row.Name
		}
		if row.Version != nil {
			version = *row.Version
		}
		if row.Port != nil {
			port = *row.Port
		}
		if row.ProtoType != nil {
			proto = *row.ProtoType
		}
		return
	}

	ln, lv, lp, lproto := normalize(linuxFixture)
	wn, wv, wp, wproto := normalize(windowsFixture)
	if ln != wn || lv != wv || lp != wp || lproto != wproto {
		t.Fatalf("fixture mismatch: linux=(%s,%s,%d,%s), windows=(%s,%s,%d,%s)", ln, lv, lp, lproto, wn, wv, wp, wproto)
	}
}
