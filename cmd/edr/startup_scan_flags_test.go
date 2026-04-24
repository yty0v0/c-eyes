package main

import "testing"

func TestParseStartupScanFlagsHelp(t *testing.T) {
	opts, err := parseStartupScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseStartupScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseStartupScanFlagsBuildParams(t *testing.T) {
	opts, err := parseStartupScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-name", "ssh",
		"-initLevel", "3,5",
		"-defaultOpen", "true,false",
		"-isXinetd", "false",
		"-showName", "Print Spooler",
		"-user", "LocalSystem",
		"-enable=true",
		"-startType", "2,3",
		"-publisher", "Microsoft",
		"-output", "excel",
		"-excel", "startup.xlsx",
	})
	if err != nil {
		t.Fatalf("parseStartupScanFlags returned error: %v", err)
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
	if opts.Params.Name == nil || *opts.Params.Name != "ssh" {
		t.Fatalf("unexpected name")
	}
	if len(opts.Params.InitLevel) != 2 || opts.Params.InitLevel[1] != 5 {
		t.Fatalf("unexpected initLevel: %+v", opts.Params.InitLevel)
	}
	if len(opts.Params.DefaultOpen) != 2 || opts.Params.DefaultOpen[0] != true || opts.Params.DefaultOpen[1] != false {
		t.Fatalf("unexpected defaultOpen: %+v", opts.Params.DefaultOpen)
	}
	if len(opts.Params.IsXinetd) != 1 || opts.Params.IsXinetd[0] != false {
		t.Fatalf("unexpected isXinetd: %+v", opts.Params.IsXinetd)
	}
	if opts.Params.ShowName == nil || *opts.Params.ShowName != "Print Spooler" {
		t.Fatalf("unexpected showName")
	}
	if opts.Params.User == nil || *opts.Params.User != "LocalSystem" {
		t.Fatalf("unexpected user")
	}
	if opts.Params.Enable == nil || *opts.Params.Enable != true {
		t.Fatalf("unexpected enable")
	}
	if len(opts.Params.StartType) != 2 || opts.Params.StartType[0] != 2 {
		t.Fatalf("unexpected startType: %+v", opts.Params.StartType)
	}
	if opts.Params.Publisher == nil || *opts.Params.Publisher != "Microsoft" {
		t.Fatalf("unexpected publisher")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "startup.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseStartupScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseStartupScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseStartupScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseStartupScanFlagsInvalidOutput(t *testing.T) {
	_, err := parseStartupScanFlags([]string{"-output", "yaml"})
	if err == nil {
		t.Fatalf("expected error for invalid output")
	}
}

func TestParseStartupScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseStartupScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}

func TestParseStartupScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseStartupScanFlags([]string{"-excel", "startup.xlsx"})
	if err != nil {
		t.Fatalf("parseStartupScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}
