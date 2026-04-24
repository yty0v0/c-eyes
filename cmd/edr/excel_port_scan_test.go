package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/portscan"
)

func TestWritePortScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "port-scan.xlsx")
	rows := []portscan.PortInfo{
		{
			Proto:       portScanStrPtr("tcp"),
			Port:        portScanIntPtr(8080),
			ProcessName: portScanStrPtr("demo"),
			BindIP:      portScanStrPtr("0.0.0.0"),
			Status:      portScanIntPtr(1),
		},
	}
	if err := writePortScanExcel(path, rows); err != nil {
		t.Fatalf("writePortScanExcel error: %v", err)
	}
}

func portScanStrPtr(v string) *string {
	return &v
}

func portScanIntPtr(v int) *int {
	return &v
}
