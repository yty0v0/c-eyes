package filescan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultCachePathUsesExecutableDir(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable error: %v", err)
	}

	got := DefaultCachePath()
	want := filepath.Join(filepath.Dir(exe), "scan-cache.db")
	if got != want {
		t.Fatalf("DefaultCachePath=%q, want %q", got, want)
	}
}
