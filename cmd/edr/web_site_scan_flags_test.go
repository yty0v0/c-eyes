package main

import "testing"

func TestParseWebSiteScanFlagsHelp(t *testing.T) {
	opts, err := parseWebSiteScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseWebSiteScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseWebSiteScanFlagsBuildParams(t *testing.T) {
	opts, err := parseWebSiteScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "web-node",
		"-ip", "192.168",
		"-port", "443",
		"-proto", "https",
		"-type", "nginx,iis",
		"-rootPath", "/var/www",
		"-output", "excel",
		"-excel", "web-site.xlsx",
	})
	if err != nil {
		t.Fatalf("parseWebSiteScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Port == nil || *opts.Params.Port != 443 {
		t.Fatalf("unexpected port")
	}
	if opts.Params.Proto == nil || *opts.Params.Proto != "https" {
		t.Fatalf("unexpected proto")
	}
	if len(opts.Params.Type) != 2 || opts.Params.Type[1] != "iis" {
		t.Fatalf("unexpected types: %+v", opts.Params.Type)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "web-site.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseWebSiteScanFlagsInvalidProto(t *testing.T) {
	_, err := parseWebSiteScanFlags([]string{"-proto", "tcp"})
	if err == nil {
		t.Fatalf("expected error for invalid proto")
	}
}

func TestParseWebSiteScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseWebSiteScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseWebSiteScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseWebSiteScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseWebSiteScanFlags([]string{"-excel", "web-site.xlsx"})
	if err != nil {
		t.Fatalf("parseWebSiteScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseWebSiteScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseWebSiteScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
