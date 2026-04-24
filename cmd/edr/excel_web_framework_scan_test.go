package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/webframescan"
)

func ptrString(v string) *string { return &v }

func ptrInt64(v int64) *int64 { return &v }

func TestWriteWebFrameworkScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-framework-scan.xlsx")
	rows := []webframescan.WebFrameRecord{
		{
			DisplayIP:      ptrString("10.10.10.5"),
			ExternalIPList: []string{"1.1.1.1"},
			InternalIPList: []string{"10.10.10.5"},
			BizGroupID:     ptrInt64(39),
			BizGroup:       ptrString("c-eyes"),
			HostTagList:    []string{"prod", "web"},
			Hostname:       ptrString("linux-web-01"),
			Name:           ptrString("tomcat"),
			Version:        ptrString("9.0.80"),
			Type:           ptrString("java"),
			ServerName:     ptrString("tomcat"),
			DomainName:     ptrString("example.com"),
			WebAppDir:      ptrString("/opt/tomcat/conf/server.xml"),
			JarCount:       ptrString("1"),
			JarList: []webframescan.JarRecord{
				{
					Version: ptrString("6.1.2"),
					AbsDir:  ptrString("/opt/tomcat/lib"),
					JarName: ptrString("spring-core-6.1.2.jar"),
				},
			},
			WebRoot: ptrString("/opt/tomcat/webapps"),
			WorkDir: ptrString("/opt/tomcat/webapps"),
		},
	}

	if err := writeWebFrameworkScanExcel(path, rows); err != nil {
		t.Fatalf("writeWebFrameworkScanExcel error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	defer func() { _ = file.Close() }()

	sheet := "web-framework-scan"
	if got, err := file.GetCellValue(sheet, "A2"); err != nil || got != "10.10.10.5" {
		t.Fatalf("unexpected displayIp cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "O2"); err != nil || got != "1" {
		t.Fatalf("unexpected jarCount cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "P2"); err != nil || got == "" {
		t.Fatalf("expected jarList json in cell P2, got %q, err=%v", got, err)
	}
}

func TestWebFrameworkJSONExcelParityAndNoRiskFields(t *testing.T) {
	row := webframescan.WebFrameRecord{
		DisplayIP:  ptrString("10.0.0.5"),
		Name:       ptrString("nginx"),
		ServerName: ptrString("nginx"),
		JarList:    []webframescan.JarRecord{},
	}
	result := webframescan.WebFrameScanResult{
		Total: 1,
		Rows:  []webframescan.WebFrameRecord{row},
	}

	var buf bytes.Buffer
	if err := webframescan.WriteJSON(&buf, result); err != nil {
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
	if jsonRow["name"] != "nginx" || jsonRow["serverName"] != "nginx" {
		t.Fatalf("unexpected json row core fields: %+v", jsonRow)
	}
	for _, forbidden := range []string{"riskLevel", "severity", "riskScore", "verdict", "alert"} {
		if _, exists := jsonRow[forbidden]; exists {
			t.Fatalf("unexpected risk field in json row: %s", forbidden)
		}
	}

	excelRow := webFrameworkScanExcelRow(row)
	if excelRow[8] != "nginx" || excelRow[11] != "nginx" {
		t.Fatalf("unexpected excel row projection: %+v", excelRow)
	}
	if excelRow[15] != "[]" {
		t.Fatalf("expected empty jarList json, got %+v", excelRow[15])
	}
}

func TestWriteWebFrameworkScanExcelUTF8Content(t *testing.T) {
	path := filepath.Join(t.TempDir(), "web-framework-scan-utf8.xlsx")
	rows := []webframescan.WebFrameRecord{
		{
			Hostname:   ptrString("测试主机"),
			Name:       ptrString("框架-测试"),
			ServerName: ptrString("tomcat"),
			DomainName: ptrString("示例.中国"),
			JarList: []webframescan.JarRecord{
				{
					Version: ptrString("1.0.0"),
					AbsDir:  ptrString("/opt/测试/lib"),
					JarName: ptrString("核心-组件.jar"),
				},
			},
			JarCount: ptrString("1"),
		},
	}

	if err := writeWebFrameworkScanExcel(path, rows); err != nil {
		t.Fatalf("writeWebFrameworkScanExcel error: %v", err)
	}

	file, err := excelize.OpenFile(path)
	if err != nil {
		t.Fatalf("open excel: %v", err)
	}
	defer func() { _ = file.Close() }()

	sheet := "web-framework-scan"
	if got, err := file.GetCellValue(sheet, "H2"); err != nil || got != "测试主机" {
		t.Fatalf("unexpected hostname cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "I2"); err != nil || got != "框架-测试" {
		t.Fatalf("unexpected name cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "M2"); err != nil || got != "示例.中国" {
		t.Fatalf("unexpected domain cell: %q, err=%v", got, err)
	}
	if got, err := file.GetCellValue(sheet, "P2"); err != nil || !bytes.Contains([]byte(got), []byte("核心-组件.jar")) {
		t.Fatalf("unexpected jarList cell: %q, err=%v", got, err)
	}
}
