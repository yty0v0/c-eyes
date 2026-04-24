package main

import (
	"path/filepath"
	"testing"
	"time"

	"edrsystem/internal/scheduledtaskscan"
)

func TestWriteScheduledTaskScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scheduled-task-scan.xlsx")
	now := time.Now().UTC()
	rows := []scheduledtaskscan.ScheduledTaskInfo{
		{
			User:      testScheduledTaskStrPtr("root"),
			ExecPath:  testScheduledTaskStrPtr("/usr/bin/backup"),
			TaskTime:  &now,
			TaskType:  testScheduledTaskStrPtr("CRONTAB"),
			CrondOpen: testScheduledTaskBoolPtr(true),
		},
	}

	if err := writeScheduledTaskScanExcel(path, rows); err != nil {
		t.Fatalf("writeScheduledTaskScanExcel error: %v", err)
	}
}

func TestScheduledTaskExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIpList",
		"internalIpList",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"user",
		"execTime",
		"execPath",
		"conf",
		"taskTime",
		"taskId",
		"taskType",
		"crondOpen",
	}
	if len(scheduledTaskScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(scheduledTaskScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if scheduledTaskScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, scheduledTaskScanExcelHeaders[i], key)
		}
	}
}

func testScheduledTaskStrPtr(v string) *string {
	return &v
}

func testScheduledTaskBoolPtr(v bool) *bool {
	return &v
}
