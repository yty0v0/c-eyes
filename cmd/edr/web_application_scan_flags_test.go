package main

import "testing"

func TestParseWebApplicationScanFlagsHelp(t *testing.T) {
	opts, err := parseWebApplicationScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseWebApplicationScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseWebApplicationScanFlagsBuildParams(t *testing.T) {
	opts, err := parseWebApplicationScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "web-node",
		"-ip", "192.168",
		"-version", "1.24.0,9.0.80",
		"-appName", "nginx",
		"-rootPath", "/etc/nginx",
		"-webRoot", "/var/www/html",
		"-serverName", "nginx,apache",
		"-domainName", "example.com",
		"-output", "excel",
		"-excel", "web-app.xlsx",
	})
	if err != nil {
		t.Fatalf("parseWebApplicationScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Hostname == nil || *opts.Params.Hostname != "web-node" {
		t.Fatalf("unexpected hostname")
	}
	if len(opts.Params.Version) != 2 || opts.Params.Version[0] != "1.24.0" {
		t.Fatalf("unexpected version: %+v", opts.Params.Version)
	}
	if len(opts.Params.ServerName) != 2 || opts.Params.ServerName[1] != "apache" {
		t.Fatalf("unexpected serverName: %+v", opts.Params.ServerName)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "web-app.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseWebApplicationScanFlagsInvalidControlChars(t *testing.T) {
	_, err := parseWebApplicationScanFlags([]string{"-domainName", "abc\ndef"})
	if err == nil {
		t.Fatalf("expected error for invalid domainName")
	}
}

func TestParseWebApplicationScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseWebApplicationScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseWebApplicationScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseWebApplicationScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseWebApplicationScanFlags([]string{"-excel", "web-app.xlsx"})
	if err != nil {
		t.Fatalf("parseWebApplicationScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseWebApplicationScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseWebApplicationScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
