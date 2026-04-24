package main

import "testing"

func TestParseFileScanFlags_InvalidMode(t *testing.T) {
	_, err := parseFileScanFlags([]string{"-mode", "bad"})
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}
}

func TestParseFileScanFlags_PathRequired(t *testing.T) {
	_, err := parseFileScanFlags([]string{"-mode", "path"})
	if err == nil {
		t.Fatalf("expected error for missing path")
	}
}

func TestParseFileScanFlags_PathProvided(t *testing.T) {
	opts, err := parseFileScanFlags([]string{"-mode", "path", "-path", "/tmp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts.Path != "/tmp" {
		t.Fatalf("unexpected path: %s", opts.Path)
	}
}
