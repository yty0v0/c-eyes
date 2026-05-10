package imagebackend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveImageTargetModeExplicitTypes(t *testing.T) {
	t.Parallel()

	mode, target, err := resolveImageTargetMode("nginx:1.27", "image")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(image) error: %v", err)
	}
	if mode != TargetModeImage || target != "nginx:1.27" {
		t.Fatalf("unexpected image mode result: mode=%s target=%q", mode, target)
	}

	mode, target, err = resolveImageTargetMode("demo.tar", "archive")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(archive) error: %v", err)
	}
	if mode != TargetModeImageArchive || target != "demo.tar" {
		t.Fatalf("unexpected archive mode result: mode=%s target=%q", mode, target)
	}

	mode, target, err = resolveImageTargetMode("layout-dir", "oci-layout")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(oci-layout) error: %v", err)
	}
	if mode != TargetModeOCILayout || target != "layout-dir" {
		t.Fatalf("unexpected oci-layout mode result: mode=%s target=%q", mode, target)
	}
}

func TestResolveImageTargetModeAutoDetectsArchiveFile(t *testing.T) {
	t.Parallel()

	file := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(file, []byte("tar"), 0o644); err != nil {
		t.Fatalf("write archive file failed: %v", err)
	}

	mode, target, err := resolveImageTargetMode(file, "auto")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(auto archive) error: %v", err)
	}
	if mode != TargetModeImageArchive || target != file {
		t.Fatalf("unexpected archive autodetect result: mode=%s target=%q", mode, target)
	}
}

func TestResolveImageTargetModeAutoDetectsOCILayoutDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("write oci-layout marker failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"schemaVersion":2,"manifests":[]}`), 0o644); err != nil {
		t.Fatalf("write OCI index failed: %v", err)
	}

	mode, target, err := resolveImageTargetMode(dir, "auto")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(auto oci-layout) error: %v", err)
	}
	if mode != TargetModeOCILayout || target != dir {
		t.Fatalf("unexpected oci-layout autodetect result: mode=%s target=%q", mode, target)
	}
}

func TestResolveImageTargetModeAutoDetectsImageReference(t *testing.T) {
	t.Parallel()

	mode, target, err := resolveImageTargetMode("nginx:1.27", "auto")
	if err != nil {
		t.Fatalf("resolveImageTargetMode(auto image) error: %v", err)
	}
	if mode != TargetModeImage || target != "nginx:1.27" {
		t.Fatalf("unexpected image autodetect result: mode=%s target=%q", mode, target)
	}
}

func TestResolveImageTargetModeRejectsMissingLocalPath(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.tar")
	_, _, err := resolveImageTargetMode(missing, "auto")
	if err == nil {
		t.Fatal("expected missing path error")
	}
}
