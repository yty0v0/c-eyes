package main

import "testing"

func TestParseEnvironmentScanFlagsHelp(t *testing.T) {
	opts, err := parseEnvironmentScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseEnvironmentScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseEnvironmentScanFlagsBuildParams(t *testing.T) {
	opts, err := parseEnvironmentScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-key", "path",
		"-value", "bin",
		"-user", "root",
		"-sysEnv", "true,false",
		"-output", "excel",
		"-excel", "environment.xlsx",
	})
	if err != nil {
		t.Fatalf("parseEnvironmentScanFlags returned error: %v", err)
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
	if opts.Params.Key == nil || *opts.Params.Key != "path" {
		t.Fatalf("unexpected key")
	}
	if opts.Params.Value == nil || *opts.Params.Value != "bin" {
		t.Fatalf("unexpected value")
	}
	if opts.Params.User == nil || *opts.Params.User != "root" {
		t.Fatalf("unexpected user")
	}
	if len(opts.Params.SysEnv) != 2 || !opts.Params.SysEnv[0] || opts.Params.SysEnv[1] {
		t.Fatalf("unexpected sysEnv: %+v", opts.Params.SysEnv)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "environment.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseEnvironmentScanFlagsInvalidSysEnv(t *testing.T) {
	_, err := parseEnvironmentScanFlags([]string{"-sysEnv", "yes,no"})
	if err == nil {
		t.Fatalf("expected error for invalid sysEnv")
	}
}

func TestParseEnvironmentScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseEnvironmentScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseEnvironmentScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseEnvironmentScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseEnvironmentScanFlags([]string{"-excel", "environment.xlsx"})
	if err != nil {
		t.Fatalf("parseEnvironmentScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseEnvironmentScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseEnvironmentScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
