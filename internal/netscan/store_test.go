package netscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStorePathUsesExecutableDir(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable error: %v", err)
	}

	got := defaultStorePath()
	want := filepath.Join(filepath.Dir(exe), "netscan-assets.db")
	if got != want {
		t.Fatalf("defaultStorePath()=%q, want %q", got, want)
	}
}
