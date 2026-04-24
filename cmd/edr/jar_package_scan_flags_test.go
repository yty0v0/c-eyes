package main

import (
	"strings"
	"testing"
)

func TestParseJarPackageScanFlagsHelp(t *testing.T) {
	opts, err := parseJarPackageScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseJarPackageScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseJarPackageScanFlagsBuildParams(t *testing.T) {
	opts, err := parseJarPackageScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "web-node",
		"-ip", "192.168",
		"-name", "spring",
		"-version", "6.1.2,3.14.0",
		"-type", "1,3",
		"-executable", "true,false",
		"-path", "/opt/lib",
		"-output", "excel",
		"-excel", "jar-package.xlsx",
	})
	if err != nil {
		t.Fatalf("parseJarPackageScanFlags returned error: %v", err)
	}
	if len(opts.Params.Groups) != 2 || opts.Params.Groups[0] != 39 {
		t.Fatalf("unexpected groups: %+v", opts.Params.Groups)
	}
	if opts.Params.Name == nil || *opts.Params.Name != "spring" {
		t.Fatalf("unexpected name")
	}
	if len(opts.Params.Version) != 2 || opts.Params.Version[1] != "3.14.0" {
		t.Fatalf("unexpected version: %+v", opts.Params.Version)
	}
	if len(opts.Params.Type) != 2 || opts.Params.Type[0] != 1 {
		t.Fatalf("unexpected type: %+v", opts.Params.Type)
	}
	if len(opts.Params.Executable) != 2 || !opts.Params.Executable[0] {
		t.Fatalf("unexpected executable: %+v", opts.Params.Executable)
	}
	if opts.Params.Path == nil || *opts.Params.Path != "/opt/lib" {
		t.Fatalf("unexpected path")
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "jar-package.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseJarPackageScanFlagsInvalidControlChars(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-name", "abc\ndef"})
	if err == nil {
		t.Fatalf("expected error for invalid name")
	}
}

func TestParseJarPackageScanFlagsInvalidTypeDomain(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-type", "9"})
	if err == nil {
		t.Fatalf("expected error for invalid type domain")
	}
}

func TestParseJarPackageScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseJarPackageScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseJarPackageScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseJarPackageScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseJarPackageScanFlags([]string{"-excel", "jar-package.xlsx"})
	if err != nil {
		t.Fatalf("parseJarPackageScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseJarPackageScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}

func TestParseJarPackageScanFlagsRejectsInvalidExecutableToken(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-executable", "true,not-bool"})
	if err == nil {
		t.Fatalf("expected error for invalid executable token")
	}
}

func TestParseJarPackageScanFlagsRejectsInvalidTypeToken(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-type", "abc"})
	if err == nil {
		t.Fatalf("expected error for non-numeric type token")
	}
}

func TestParseJarPackageScanFlagsRejectsPathControlChar(t *testing.T) {
	_, err := parseJarPackageScanFlags([]string{"-path", "/opt/lib/\nmalicious.jar"})
	if err == nil {
		t.Fatalf("expected error for control chars in path")
	}
}

func TestParseJarPackageScanFlagsLargeAdversarialInputDoesNotPanic(t *testing.T) {
	longName := strings.Repeat("jar", 3000) + ".jar"
	_, err := parseJarPackageScanFlags([]string{
		"-name", longName,
		"-version", "1.0.0,2.0.0,3.0.0",
		"-type", "1,2,3,8",
		"-executable", "true,false",
		"-path", "/opt/services/" + longName,
	})
	if err != nil {
		t.Fatalf("expected parser to handle large but valid input, got error: %v", err)
	}
}
