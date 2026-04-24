package main

import "testing"

func TestParseAccountScanFlagsHelp(t *testing.T) {
	opts, err := parseAccountScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseAccountScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseAccountScanFlagsBuildParams(t *testing.T) {
	opts, err := parseAccountScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-status", "0,1",
		"-name", "alice",
		"-home", "/home",
		"-lastLoginFrom", "2026-01-01",
		"-lastLoginTo", "2026-12-31",
		"-gid", "1000",
		"-uid", "1001",
		"-output", "excel",
		"-excel", "account.xlsx",
	})
	if err != nil {
		t.Fatalf("parseAccountScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Hostname == nil || *opts.Params.Hostname != "node" {
		t.Fatalf("unexpected hostname")
	}
	if opts.Params.LastLoginTime == nil || opts.Params.LastLoginTime.From == nil || opts.Params.LastLoginTime.To == nil {
		t.Fatalf("expected date range")
	}
	if opts.Params.GID == nil || *opts.Params.GID != 1000 {
		t.Fatalf("unexpected gid")
	}
	if opts.Params.UID == nil || *opts.Params.UID != 1001 {
		t.Fatalf("unexpected uid")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "account.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseAccountScanFlagsInvalidGID(t *testing.T) {
	_, err := parseAccountScanFlags([]string{"-gid", "bad"})
	if err == nil {
		t.Fatalf("expected error for invalid gid")
	}
}

func TestParseAccountScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseAccountScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseAccountScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseAccountScanFlagsInvalidOutput(t *testing.T) {
	_, err := parseAccountScanFlags([]string{"-output", "yaml"})
	if err == nil {
		t.Fatalf("expected error for invalid output")
	}
}

func TestParseAccountScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseAccountScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}

func TestParseAccountScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseAccountScanFlags([]string{"-excel", "account.xlsx"})
	if err != nil {
		t.Fatalf("parseAccountScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "account.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}
