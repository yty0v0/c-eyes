package main

import "testing"

func TestParseUserGroupScanFlagsHelp(t *testing.T) {
	opts, err := parseUserGroupScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseUserGroupScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseUserGroupScanFlagsBuildParams(t *testing.T) {
	opts, err := parseUserGroupScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-name", "admin",
		"-gid", "1000",
		"-output", "excel",
		"-excel", "group.xlsx",
	})
	if err != nil {
		t.Fatalf("parseUserGroupScanFlags returned error: %v", err)
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
	if opts.Params.Name == nil || *opts.Params.Name != "admin" {
		t.Fatalf("unexpected name")
	}
	if opts.Params.GID == nil || *opts.Params.GID != 1000 {
		t.Fatalf("unexpected gid")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "group.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseUserGroupScanFlagsInvalidGID(t *testing.T) {
	_, err := parseUserGroupScanFlags([]string{"-gid", "bad"})
	if err == nil {
		t.Fatalf("expected error for invalid gid")
	}
}

func TestParseUserGroupScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseUserGroupScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseUserGroupScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseUserGroupScanFlagsInvalidOutput(t *testing.T) {
	_, err := parseUserGroupScanFlags([]string{"-output", "yaml"})
	if err == nil {
		t.Fatalf("expected error for invalid output")
	}
}

func TestParseUserGroupScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseUserGroupScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}

func TestParseUserGroupScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseUserGroupScanFlags([]string{"-excel", "group.xlsx"})
	if err != nil {
		t.Fatalf("parseUserGroupScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "group.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}
