//go:build !windows

package filescan

import (
	"os"
	"testing"
)

func TestELFBinaryInfo(t *testing.T) {
	path := pickUnixCandidate(t, func(path string) bool {
		info := binaryInfo(path)
		if info == nil || info.MagicBytes == nil {
			return false
		}
		if *info.MagicBytes != "7F 45 4C 46" {
			return false
		}
		if len(info.SectionsInfo) == 0 {
			return false
		}
		if len(info.ImportedLibraries) == 0 {
			return false
		}
		return true
	})

	info := binaryInfo(path)
	if info == nil || info.MagicBytes == nil || *info.MagicBytes != "7F 45 4C 46" {
		t.Fatalf("expected ELF magic for %s", path)
	}
	if len(info.SectionsInfo) == 0 {
		t.Fatalf("expected section info for %s", path)
	}
	if len(info.ImportedLibraries) == 0 {
		t.Fatalf("expected imported libraries for %s", path)
	}
}

func TestELFImphash(t *testing.T) {
	path := pickUnixCandidate(t, func(path string) bool {
		hash := imphashForFile(path)
		return hash != nil && len(*hash) == 32
	})
	hash := imphashForFile(path)
	if hash == nil || len(*hash) != 32 {
		t.Fatalf("expected imphash for ELF: %s", path)
	}
	if info := peVersionInfo(path); info != nil {
		t.Fatalf("expected version_info nil for ELF: %s", path)
	}
}

func pickUnixCandidate(t *testing.T, accept func(path string) bool) string {
	t.Helper()
	candidates := []string{
		"/bin/ls",
		"/usr/bin/ls",
		"/bin/bash",
		"/usr/bin/env",
		"/bin/sh",
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if accept == nil || accept(path) {
			return path
		}
	}
	t.Skip("no suitable ELF binary found for test")
	return ""
}
