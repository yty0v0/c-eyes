package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/databasescan"
)

func TestWriteDatabaseScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database-scan.xlsx")
	rows := []databasescan.DatabaseRecord{
		{
			Name:    testDatabaseStrPtr("MySQL"),
			Version: testDatabaseStrPtr("8.0"),
			Port:    testDatabaseIntPtr(3306),
		},
	}
	if err := writeDatabaseScanExcel(path, rows); err != nil {
		t.Fatalf("writeDatabaseScanExcel error: %v", err)
	}
}

func TestDatabaseExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIpList",
		"internalIpList",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"name",
		"version",
		"port",
		"protoType",
		"user",
		"bindIp",
		"confPath",
		"logPath",
		"dataDir",
		"pluginDir",
		"rest",
		"auth",
		"web",
		"webPort",
		"webAddress",
		"regionServer",
		"dbName",
		"loginModel",
		"auditLevel",
		"sysLogPath",
		"mainDbPath",
	}
	if len(databaseScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(databaseScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if databaseScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, databaseScanExcelHeaders[i], key)
		}
	}
}

func testDatabaseStrPtr(v string) *string {
	return &v
}

func testDatabaseIntPtr(v int) *int {
	return &v
}
