package main

import "testing"

func TestParseDatabaseScanFlagsHelp(t *testing.T) {
	opts, err := parseDatabaseScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseDatabaseScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseDatabaseScanFlagsBuildParams(t *testing.T) {
	opts, err := parseDatabaseScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "db-node",
		"-ip", "192.168",
		"-name", "mysql",
		"-versions", "8.0,5.7",
		"-port", "3306",
		"-confPath", "/etc/mysql",
		"-logPath", "/var/log/mysql",
		"-dataDir", "/var/lib/mysql",
		"-output", "excel",
		"-excel", "database.xlsx",
	})
	if err != nil {
		t.Fatalf("parseDatabaseScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Name == nil || *opts.Params.Name != "mysql" {
		t.Fatalf("unexpected name")
	}
	if len(opts.Params.Versions) != 2 || opts.Params.Versions[0] != "8.0" {
		t.Fatalf("unexpected versions: %+v", opts.Params.Versions)
	}
	if opts.Params.Port == nil || *opts.Params.Port != 3306 {
		t.Fatalf("unexpected port")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "database.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseDatabaseScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseDatabaseScanFlags(nil)
	if err != nil {
		t.Fatalf("parseDatabaseScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected output=json, got %q", opts.OutputFormat)
	}
}

func TestParseDatabaseScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseDatabaseScanFlags([]string{"-excel", "database.xlsx"})
	if err != nil {
		t.Fatalf("parseDatabaseScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel provided, got %q", opts.OutputFormat)
	}
}

func TestParseDatabaseScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseDatabaseScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
