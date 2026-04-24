package main

import (
	"fmt"
	"path/filepath"
	"testing"

	"edrsystem/internal/environmentscan"
)

func TestWriteEnvironmentScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment-scan.xlsx")
	rows := []environmentscan.EnvironmentInfo{
		{
			Key:    testEnvironmentStrPtr("PATH"),
			Value:  testEnvironmentStrPtr("/usr/local/bin:/usr/bin"),
			User:   testEnvironmentStrPtr("root"),
			SysEnv: testEnvironmentBoolPtr(true),
		},
	}

	if err := writeEnvironmentScanExcel(path, rows); err != nil {
		t.Fatalf("writeEnvironmentScanExcel error: %v", err)
	}
}

func TestEnvironmentExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIpList",
		"internalIpList",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"key",
		"value",
		"user",
		"sysEnv",
	}
	if len(environmentScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(environmentScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if environmentScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, environmentScanExcelHeaders[i], key)
		}
	}
}

func TestWriteEnvironmentScanExcelLargeDataset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment-large.xlsx")
	rows := make([]environmentscan.EnvironmentInfo, 0, 2000)
	for i := 0; i < 2000; i++ {
		key := fmt.Sprintf("KEY_%d", i)
		value := fmt.Sprintf("VALUE_%d", i)
		user := "root"
		sysEnv := i%2 == 0
		rows = append(rows, environmentscan.EnvironmentInfo{
			Key:    &key,
			Value:  &value,
			User:   &user,
			SysEnv: &sysEnv,
		})
	}

	if err := writeEnvironmentScanExcel(path, rows); err != nil {
		t.Fatalf("writeEnvironmentScanExcel large dataset error: %v", err)
	}
}

func testEnvironmentStrPtr(v string) *string {
	return &v
}

func testEnvironmentBoolPtr(v bool) *bool {
	return &v
}
