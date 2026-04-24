package main

import "testing"

func TestParseWebFrameworkScanFlagsHelp(t *testing.T) {
	opts, err := parseWebFrameworkScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseWebFrameworkScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseWebFrameworkScanFlagsBuildParams(t *testing.T) {
	opts, err := parseWebFrameworkScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "web-node",
		"-ip", "192.168",
		"-name", "tomcat",
		"-version", "9.0.80",
		"-type", "java,python",
		"-serverName", "tomcat,nginx",
		"-output", "excel",
		"-excel", "web-frame.xlsx",
	})
	if err != nil {
		t.Fatalf("parseWebFrameworkScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Name == nil || *opts.Params.Name != "tomcat" {
		t.Fatalf("unexpected name")
	}
	if opts.Params.Version == nil || *opts.Params.Version != "9.0.80" {
		t.Fatalf("unexpected version")
	}
	if len(opts.Params.Type) != 2 || opts.Params.Type[0] != "java" {
		t.Fatalf("unexpected type: %+v", opts.Params.Type)
	}
	if len(opts.Params.ServerName) != 2 || opts.Params.ServerName[1] != "nginx" {
		t.Fatalf("unexpected serverName: %+v", opts.Params.ServerName)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "web-frame.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseWebFrameworkScanFlagsInvalidControlChars(t *testing.T) {
	_, err := parseWebFrameworkScanFlags([]string{"-name", "abc\ndef"})
	if err == nil {
		t.Fatalf("expected error for invalid name")
	}
}

func TestParseWebFrameworkScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseWebFrameworkScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseWebFrameworkScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseWebFrameworkScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseWebFrameworkScanFlags([]string{"-excel", "web-frame.xlsx"})
	if err != nil {
		t.Fatalf("parseWebFrameworkScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseWebFrameworkScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseWebFrameworkScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
