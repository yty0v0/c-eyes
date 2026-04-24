package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer readPipe.Close()

	os.Stderr = writePipe
	defer func() {
		os.Stderr = origStderr
	}()

	outputCh := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, readPipe)
		outputCh <- buf.String()
	}()

	fn()
	_ = writePipe.Close()
	return <-outputCh
}

func TestParseProcessScanFlagsHelpShowsAllFlags(t *testing.T) {
	var (
		opts processScanOptions
		err  error
	)
	output := captureStderr(t, func() {
		opts, err = parseProcessScanFlags([]string{"-h"})
	})
	if err != nil {
		t.Fatalf("parseProcessScanFlags returned error: %v", err)
	}
	if !opts.ShowHelp {
		t.Fatal("expected ShowHelp=true")
	}
	for _, expected := range []string{"-hostname", "-ip", "-startTime", "-pids", "-types", "-excel"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("help output missing flag %q: %s", expected, output)
		}
	}
}

func TestParseProcessScanFlagsBuildsParams(t *testing.T) {
	opts, err := parseProcessScanFlags([]string{
		"-hostname", "srv",
		"-startTime", "2026-03-01",
		"-pids", "123,456",
		"-root",
		"-excel", "out.xlsx",
	})
	if err != nil {
		t.Fatalf("parseProcessScanFlags returned error: %v", err)
	}
	if opts.Params.Hostname == nil || *opts.Params.Hostname != "srv" {
		t.Fatalf("expected hostname=srv, got %+v", opts.Params.Hostname)
	}
	if opts.Params.StartTime == nil || opts.Params.StartTime.Year() != 2026 {
		t.Fatalf("expected parsed startTime year 2026, got %+v", opts.Params.StartTime)
	}
	if len(opts.Params.PIDs) != 2 || opts.Params.PIDs[0] != 123 || opts.Params.PIDs[1] != 456 {
		t.Fatalf("unexpected pids: %+v", opts.Params.PIDs)
	}
	if opts.Params.Root == nil || !*opts.Params.Root {
		t.Fatalf("expected root=true, got %+v", opts.Params.Root)
	}
	if opts.ExcelPath != "out.xlsx" {
		t.Fatalf("expected excel path out.xlsx, got %q", opts.ExcelPath)
	}
}
