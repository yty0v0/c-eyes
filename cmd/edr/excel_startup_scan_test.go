package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/startupscan"
)

func TestWriteStartupScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup-scan.xlsx")
	rows := []startupscan.StartupInfo{
		{
			Name:        startupScanStrPtr("sshd"),
			DefaultOpen: startupScanBoolPtr(true),
			RC3:         startupScanIntPtr(1),
			InitLevel:   startupScanIntPtr(3),
			Xinetd:      startupScanBoolPtr(false),
		},
	}

	if err := writeStartupScanExcel(path, rows); err != nil {
		t.Fatalf("writeStartupScanExcel error: %v", err)
	}
}

func startupScanStrPtr(v string) *string {
	return &v
}

func startupScanIntPtr(v int) *int {
	return &v
}

func startupScanBoolPtr(v bool) *bool {
	return &v
}
