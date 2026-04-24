package main

import "testing"

func TestParsePortScanFlagsHelp(t *testing.T) {
	opts, err := parsePortScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parsePortScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParsePortScanFlagsBuildParams(t *testing.T) {
	opts, err := parsePortScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-proto", "tcp,tcp6",
		"-port", "443",
		"-bindIp", "0.0.0.0",
		"-processName", "nginx",
		"-mode", "tcp-syn",
		"-output", "excel",
		"-excel", "port.xlsx",
	})
	if err != nil {
		t.Fatalf("parsePortScanFlags returned error: %v", err)
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
	if len(opts.Params.Protos) != 2 || opts.Params.Protos[1] != "tcp6" {
		t.Fatalf("unexpected protos: %+v", opts.Params.Protos)
	}
	if opts.Params.Port == nil || *opts.Params.Port != 443 {
		t.Fatalf("unexpected port")
	}
	if opts.Params.BindIP == nil || *opts.Params.BindIP != "0.0.0.0" {
		t.Fatalf("unexpected bindIp")
	}
	if opts.Params.ProcessName == nil || *opts.Params.ProcessName != "nginx" {
		t.Fatalf("unexpected processName")
	}
	if string(opts.Params.Mode) != "tcp-syn" {
		t.Fatalf("unexpected mode: %s", opts.Params.Mode)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "port.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParsePortScanFlagsDefaultOutputAndMode(t *testing.T) {
	opts, err := parsePortScanFlags([]string{})
	if err != nil {
		t.Fatalf("parsePortScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
	if string(opts.Params.Mode) != "tcp-connect" {
		t.Fatalf("expected default mode tcp-connect, got %s", opts.Params.Mode)
	}
}

func TestParsePortScanFlagsInvalidMode(t *testing.T) {
	_, err := parsePortScanFlags([]string{"-mode", "udp"})
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}
}

func TestParsePortScanFlagsInvalidOutput(t *testing.T) {
	_, err := parsePortScanFlags([]string{"-output", "yaml"})
	if err == nil {
		t.Fatalf("expected error for invalid output")
	}
}

func TestParsePortScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parsePortScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}

func TestParsePortScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parsePortScanFlags([]string{"-excel", "port.xlsx"})
	if err != nil {
		t.Fatalf("parsePortScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}
