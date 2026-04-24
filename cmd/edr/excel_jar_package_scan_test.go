package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/jarpackagescan"
)

func TestWriteJarPackageScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jar-package-scan.xlsx")
	rows := []jarpackagescan.JarPackageRecord{
		{
			DisplayIP:      ptrString("10.10.10.5"),
			ExternalIPList: []string{"1.1.1.1"},
			InternalIPList: []string{"10.10.10.5"},
			BizGroupID:     ptrInt64(39),
			BizGroup:       ptrString("c-eyes"),
			HostTagList:    []string{"prod", "web"},
			Hostname:       ptrString("linux-web-01"),
			Name:           ptrString("spring-core-6.1.2.jar"),
			Version:        ptrString("6.1.2"),
			Type:           ptrInt(3),
			Executable:     ptrBool(false),
			Path:           ptrString("/opt/tomcat/lib/spring-core-6.1.2.jar"),
		},
	}

	if err := writeJarPackageScanExcel(path, rows); err != nil {
		t.Fatalf("writeJarPackageScanExcel error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	defer func() { _ = file.Close() }()

	sheet := "jar-package-scan"
	if got, err := file.GetCellValue(sheet, "A2"); err != nil || got != "10.10.10.5" {
		t.Fatalf("unexpected displayIp cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "K2"); err != nil || got != "3" {
		t.Fatalf("unexpected type cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "M2"); err != nil || got != "/opt/tomcat/lib/spring-core-6.1.2.jar" {
		t.Fatalf("unexpected path cell: %q, err=%v", got, err)
	}
}

func TestJarPackageJSONExcelParityAndNoRiskFields(t *testing.T) {
	row := jarpackagescan.JarPackageRecord{
		DisplayIP:  ptrString("10.0.0.5"),
		Name:       ptrString("nginx.jar"),
		Type:       ptrInt(3),
		Executable: ptrBool(false),
		Path:       ptrString("/opt/web/nginx.jar"),
	}
	result := jarpackagescan.JarPackageScanResult{
		Total: 1,
		Rows:  []jarpackagescan.JarPackageRecord{row},
	}

	var buf bytes.Buffer
	if err := jarpackagescan.WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	rowsAny, ok := decoded["rows"].([]any)
	if !ok || len(rowsAny) != 1 {
		t.Fatalf("expected rows array in json")
	}
	jsonRow, ok := rowsAny[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first row object")
	}
	if jsonRow["name"] != "nginx.jar" {
		t.Fatalf("unexpected json row name: %+v", jsonRow)
	}
	for _, forbidden := range []string{"riskLevel", "severity", "riskScore", "verdict", "alert"} {
		if _, exists := jsonRow[forbidden]; exists {
			t.Fatalf("unexpected risk field in json row: %s", forbidden)
		}
	}

	excelRow := jarPackageScanExcelRow(row)
	if excelRow[8] != "nginx.jar" || excelRow[10] != 3 {
		t.Fatalf("unexpected excel row projection: %+v", excelRow)
	}
	if excelRow[12] != "/opt/web/nginx.jar" {
		t.Fatalf("unexpected excel path projection: %+v", excelRow[12])
	}
}

func TestWriteJarPackageScanExcelUTF8Content(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jar-package-scan-utf8.xlsx")
	rows := []jarpackagescan.JarPackageRecord{
		{
			Hostname: ptrString("\u6d4b\u8bd5\u4e3b\u673a"),
			Name:     ptrString("\u6838\u5fc3\u7ec4\u4ef6.jar"),
			Path:     ptrString("/opt/\u6d4b\u8bd5/\u6838\u5fc3\u7ec4\u4ef6.jar"),
			Type:     ptrInt(8),
		},
	}

	if err := writeJarPackageScanExcel(path, rows); err != nil {
		t.Fatalf("writeJarPackageScanExcel error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	defer func() { _ = file.Close() }()

	sheet := "jar-package-scan"
	if got, err := file.GetCellValue(sheet, "H2"); err != nil || got != "测试主机" {
		t.Fatalf("unexpected hostname cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "I2"); err != nil || got != "核心组件.jar" {
		t.Fatalf("unexpected name cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "M2"); err != nil || !bytes.Contains([]byte(got), []byte("核心组件.jar")) {
		t.Fatalf("unexpected path cell: %q, err=%v", got, err)
	}
}

func ptrInt(v int) *int { return &v }

func ptrBool(v bool) *bool { return &v }
