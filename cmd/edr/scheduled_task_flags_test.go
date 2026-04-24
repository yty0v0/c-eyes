package main

import "testing"

func TestParseScheduledTaskScanFlagsHelp(t *testing.T) {
	opts, err := parseScheduledTaskScanFlags([]string{"-h"})
	if err != nil {
		t.Fatalf("parseScheduledTaskScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatalf("expected ShowHelp=true")
	}
}

func TestParseScheduledTaskScanFlagsBuildParams(t *testing.T) {
	opts, err := parseScheduledTaskScanFlags([]string{
		"-groups", "39,40",
		"-hostname", "node",
		"-ip", "192.168",
		"-user", "root,SYSTEM",
		"-execPath", "backup",
		"-conf", "crontab",
		"-taskTimeFrom", "2026-03-01",
		"-taskTimeTo", "2026-03-31",
		"-taskType", "CRONTAB,AT",
		"-output", "excel",
		"-excel", "scheduled.xlsx",
	})
	if err != nil {
		t.Fatalf("parseScheduledTaskScanFlags returned error: %v", err)
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
	if len(opts.Params.User) != 2 || opts.Params.User[1] != "SYSTEM" {
		t.Fatalf("unexpected users: %+v", opts.Params.User)
	}
	if opts.Params.ExecPath == nil || *opts.Params.ExecPath != "backup" {
		t.Fatalf("unexpected execPath")
	}
	if opts.Params.Conf == nil || *opts.Params.Conf != "crontab" {
		t.Fatalf("unexpected conf")
	}
	if opts.Params.TaskTime == nil || opts.Params.TaskTime.From == nil || opts.Params.TaskTime.To == nil {
		t.Fatalf("expected taskTime range")
	}
	if len(opts.Params.TaskType) != 2 || opts.Params.TaskType[0] != "CRONTAB" {
		t.Fatalf("unexpected taskType: %+v", opts.Params.TaskType)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel, got %q", opts.OutputFormat)
	}
	if opts.ExcelPath != "scheduled.xlsx" {
		t.Fatalf("unexpected excel path: %s", opts.ExcelPath)
	}
}

func TestParseScheduledTaskScanFlagsInvalidTaskType(t *testing.T) {
	_, err := parseScheduledTaskScanFlags([]string{"-taskType", "SYSTEMD"})
	if err == nil {
		t.Fatalf("expected error for invalid taskType")
	}
}

func TestParseScheduledTaskScanFlagsDefaultOutput(t *testing.T) {
	opts, err := parseScheduledTaskScanFlags([]string{})
	if err != nil {
		t.Fatalf("parseScheduledTaskScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "json" {
		t.Fatalf("expected default output json, got %q", opts.OutputFormat)
	}
}

func TestParseScheduledTaskScanFlagsExcelPathImpliesExcelOutput(t *testing.T) {
	opts, err := parseScheduledTaskScanFlags([]string{"-excel", "scheduled.xlsx"})
	if err != nil {
		t.Fatalf("parseScheduledTaskScanFlags returned error: %v", err)
	}
	if opts.OutputFormat != "excel" {
		t.Fatalf("expected output=excel when -excel is provided, got %q", opts.OutputFormat)
	}
}

func TestParseScheduledTaskScanFlagsExcelRequiresPath(t *testing.T) {
	_, err := parseScheduledTaskScanFlags([]string{"-output", "excel"})
	if err == nil {
		t.Fatalf("expected error for missing excel path")
	}
}
