package main

import "testing"

func TestParseSoftwareScanFlagsHelp(t *testing.T) {
	opts, err := parseSoftwareScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseSoftwareScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseSoftwareScanFlagsBuildParams(t *testing.T) {
	opts, err := parseSoftwareScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node-a",
		"-ip", "10.0",
		"-name", "nginx",
		"-version", "1.24.0,1.25.1",
		"-binPath", "/usr/sbin/nginx",
		"-configPath", "/etc/nginx/nginx.conf",
		"-output", "excel",
		"-excel", "software.xlsx",
	})
	if err != nil {
		t.Fatalf("parseSoftwareScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Name == nil || *opts.Params.Name != "nginx" {
		t.Fatalf("unexpected name")
	}
	if len(opts.Params.Version) != 2 || opts.Params.Version[1] != "1.25.1" {
		t.Fatalf("unexpected versions: %+v", opts.Params.Version)
	}
	if opts.Params.BinPath == nil || *opts.Params.BinPath != "/usr/sbin/nginx" {
		t.Fatalf("unexpected binPath")
	}
	if opts.Params.ConfigPath == nil || *opts.Params.ConfigPath != "/etc/nginx/nginx.conf" {
		t.Fatalf("unexpected configPath")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "software.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseSoftwareScanFlagsInvalidControlChars(t *testing.T) {
	_, err := parseSoftwareScanFlags([]string{"-name", "abc\ndef"})
	if err == nil {
		t.Fatalf("expected error for invalid name")
	}
}

func TestParseSoftwareScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseSoftwareScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseSoftwareScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseSoftwareScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseSoftwareScanFlags([]string{"-excel", "software.xlsx"})
	if err != nil {
		t.Fatalf("parseSoftwareScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseSoftwareScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseSoftwareScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
