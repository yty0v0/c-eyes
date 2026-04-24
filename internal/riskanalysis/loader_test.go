package riskanalysis

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestLoadScanRecordsJSONArray(t *testing.T) {
	input := `[{"scan_id":"a"},{"scan_id":"b","extra":123}]`
	path := writeTempFile(t, input)

	records, err := LoadScanRecords(path)
	if err != nil {
		t.Fatalf("LoadScanRecords error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Raw["scan_id"] != "a" {
		t.Fatalf("expected first record scan_id=a")
	}
}

func TestLoadScanRecordsNDJSON(t *testing.T) {
	input := strings.Join([]string{
		`{"scan_id":"a"}`,
		`{"scan_id":"b"}`,
		"",
	}, "\n")
	path := writeTempFile(t, input)

	records, err := LoadScanRecords(path)
	if err != nil {
		t.Fatalf("LoadScanRecords error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestLoadScanRecordsExcelFileScanFormat(t *testing.T) {
	path := writeTempExcelFile(t)

	records, err := LoadScanRecords(path)
	if err != nil {
		t.Fatalf("LoadScanRecords error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	raw := records[0].Raw
	basic, ok := raw["basic_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected basic_info object in record")
	}
	if got := basic["file_path"]; got != "C:/tmp/sample.bin" {
		t.Fatalf("unexpected basic_info.file_path: %v", got)
	}
	hashes, ok := raw["hashes"].(map[string]any)
	if !ok {
		t.Fatalf("expected hashes object in record")
	}
	if got := hashes["sha256"]; got != "abc123" {
		t.Fatalf("unexpected hashes.sha256: %v", got)
	}
	binary, ok := raw["binary_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected binary_info object in record")
	}
	if _, ok := binary["version_info"].(map[string]any); !ok {
		t.Fatalf("expected binary_info.version_info to be parsed as json object")
	}
}

func TestLoadScanRecordsCSVFileScanFormat(t *testing.T) {
	path := writeTempCSVFile(t)

	records, err := LoadScanRecords(path)
	if err != nil {
		t.Fatalf("LoadScanRecords error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	raw := records[0].Raw
	basic, ok := raw["basic_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected basic_info object in record")
	}
	if got := basic["file_path"]; got != "C:/tmp/sample.bin" {
		t.Fatalf("unexpected basic_info.file_path: %v", got)
	}
	if got := basic["file_size_bytes"]; got != int64(1234) {
		t.Fatalf("unexpected basic_info.file_size_bytes: %v", got)
	}
	hashes, ok := raw["hashes"].(map[string]any)
	if !ok {
		t.Fatalf("expected hashes object in record")
	}
	if got := hashes["sha256"]; got != "abc123" {
		t.Fatalf("unexpected hashes.sha256: %v", got)
	}
	binary, ok := raw["binary_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected binary_info object in record")
	}
	if _, ok := binary["version_info"].(map[string]any); !ok {
		t.Fatalf("expected binary_info.version_info to be parsed as json object")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	file, err := os.CreateTemp("", "risk-analysis-*.json")
	if err != nil {
		t.Fatalf("CreateTemp error: %v", err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("WriteString error: %v", err)
	}
	return file.Name()
}

func writeTempCSVFile(t *testing.T) string {
	t.Helper()
	path := writeTempFile(t, "")
	path = strings.TrimSuffix(path, ".json") + ".csv"
	_ = os.Remove(path)

	content := strings.Join([]string{
		"\uFEFFscan_mode,basic_info.file_path,basic_info.file_size_bytes,hashes.sha256,binary_info.version_info",
		`smart,C:/tmp/sample.bin,1234,abc123,"{""product_name"":""sample""}"`,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func writeTempExcelFile(t *testing.T) string {
	t.Helper()
	path := writeTempFile(t, "")
	path = strings.TrimSuffix(path, ".json") + ".xlsx"
	_ = os.Remove(path)

	file := excelize.NewFile()
	sheet := "files"
	file.SetSheetName("Sheet1", sheet)
	headers := []string{
		"scan_mode",
		"basic_info.file_path",
		"basic_info.file_size_bytes",
		"hashes.sha256",
		"binary_info.version_info",
	}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, h)
	}
	values := []any{
		"smart",
		"C:/tmp/sample.bin",
		"1234",
		"abc123",
		`{"product_name":"sample"}`,
	}
	for i, v := range values {
		cell, _ := excelize.CoordinatesToCellName(i+1, 2)
		_ = file.SetCellValue(sheet, cell, v)
	}
	if err := file.SaveAs(path); err != nil {
		t.Fatalf("SaveAs error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func TestParseExcelCellValueJSON(t *testing.T) {
	val := parseExcelCellValue(`{"k":"v"}`)
	obj, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("expected map value")
	}
	if obj["k"] != "v" {
		t.Fatalf("unexpected map value: %v", obj["k"])
	}

	arrVal := parseExcelCellValue(`[1,2]`)
	list, ok := arrVal.([]any)
	if !ok || len(list) != 2 {
		b, _ := json.Marshal(arrVal)
		t.Fatalf("unexpected array parse result: %s", string(b))
	}
}
