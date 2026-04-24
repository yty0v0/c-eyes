package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/kernelscan"
)

func TestWriteKernelScanExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kernel-scan.xlsx")
	rows := []kernelscan.KernelModuleInfo{
		{
			ModuleName: kernelScanStrPtr("tcpip"),
			Path:       kernelScanStrPtr(`C:\Windows\System32\drivers\tcpip.sys`),
			Version:    kernelScanStrPtr("10.0.26100.1"),
			Size:       kernelScanStrPtr("123456"),
			Depends:    []string{"ndis"},
			Holders:    []string{"fwpkclnt"},
		},
	}

	if err := writeKernelScanExcel(path, rows); err != nil {
		t.Fatalf("writeKernelScanExcel error: %v", err)
	}
}

func TestKernelScanExcelHeadersMatchJSONKeys(t *testing.T) {
	expected := []string{
		"displayIp",
		"externalIps",
		"internalIps",
		"bizGroupId",
		"bizGroup",
		"remark",
		"hostTagList",
		"hostname",
		"moduleName",
		"description",
		"path",
		"version",
		"size",
		"depends",
		"holders",
	}
	if len(kernelScanExcelHeaders) != len(expected) {
		t.Fatalf("unexpected header count: got %d want %d", len(kernelScanExcelHeaders), len(expected))
	}
	for i, key := range expected {
		if kernelScanExcelHeaders[i] != key {
			t.Fatalf("header mismatch at %d: got %s want %s", i, kernelScanExcelHeaders[i], key)
		}
	}
}

func kernelScanStrPtr(v string) *string {
	return &v
}
