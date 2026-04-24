package main

import "testing"

func TestParseKernelScanFlagsHelp(t *testing.T) {
	opts, err := parseKernelScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseKernelScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseKernelScanFlagsBuildParams(t *testing.T) {
	opts, err := parseKernelScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-moduleName", "tcp",
		"-path", "drivers",
		"-version", "1.0,2.0",
		"-output", "excel",
		"-excel", "kernel.xlsx",
	})
	if err != nil {
		t.Fatalf("parseKernelScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Hostname == nil || *opts.Params.Hostname != "node" {
		t.Fatalf("unexpected hostname")
	}
	if opts.Params.IP == nil || *opts.Params.IP != "192.168" {
		t.Fatalf("unexpected ip")
	}
	if opts.Params.ModuleName == nil || *opts.Params.ModuleName != "tcp" {
		t.Fatalf("unexpected moduleName")
	}
	if opts.Params.Path == nil || *opts.Params.Path != "drivers" {
		t.Fatalf("unexpected path")
	}
	if len(opts.Params.Version) != 2 || opts.Params.Version[1] != "2.0" {
		t.Fatalf("unexpected version: %+v", opts.Params.Version)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "kernel.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseKernelScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseKernelScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseKernelScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseKernelScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseKernelScanFlags([]string{"-excel", "kernel.xlsx"})
	if err != nil {
		t.Fatalf("parseKernelScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseKernelScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseKernelScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
