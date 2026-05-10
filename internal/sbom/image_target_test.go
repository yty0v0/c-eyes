package sbom

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestScanImageArchiveModeReturnsSBOMPayload(t *testing.T) {
	t.Parallel()

	archivePath := filepath.Join(t.TempDir(), "image.tar")
	img := mustNewTestImage(t)
	tag := mustTag(t, "example.com/demo:latest")
	if err := tarball.WriteToFile(archivePath, tag, img); err != nil {
		t.Fatalf("write image archive failed: %v", err)
	}

	payload, err := Scan(context.Background(), ScanOptions{
		ImageTarget: archivePath,
		Format:      FormatXSPDXJSON,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	verifySBOMPayloadHasNoRiskFields(t, payload)
}

func TestScanOCILayoutModeReturnsSBOMPayload(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lp, err := layout.Write(root, empty.Index)
	if err != nil {
		t.Fatalf("create oci layout failed: %v", err)
	}
	img := mustNewTestImage(t)
	if err := lp.AppendImage(img); err != nil {
		t.Fatalf("append image failed: %v", err)
	}

	payload, err := Scan(context.Background(), ScanOptions{
		ImageTarget: root,
		Format:      FormatXSPDXJSON,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	verifySBOMPayloadHasNoRiskFields(t, payload)
}

func TestScanOCILayoutModeSelectsTaggedImageRef(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	lp, err := layout.Write(root, empty.Index)
	if err != nil {
		t.Fatalf("create oci layout failed: %v", err)
	}

	first := mustNewTaggedTestImage(t, "first-demo", "1.0.0")
	second := mustNewTaggedTestImage(t, "second-demo", "2.0.0")
	if err := lp.AppendImage(first, layout.WithAnnotations(map[string]string{"org.opencontainers.image.ref.name": "first"})); err != nil {
		t.Fatalf("append first image failed: %v", err)
	}
	if err := lp.AppendImage(second, layout.WithAnnotations(map[string]string{"org.opencontainers.image.ref.name": "second"})); err != nil {
		t.Fatalf("append second image failed: %v", err)
	}

	payload, err := Scan(context.Background(), ScanOptions{
		ImageTarget: root + ":second",
		Format:      FormatXSPDXJSON,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	verifySBOMPayloadHasNoRiskFields(t, payload)
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}
	if !strings.Contains(string(data), "second-demo") {
		t.Fatalf("expected selected OCI image payload to contain second-demo, got: %s", string(data))
	}
}

func TestScanImageReferenceModeReturnsExplicitErrorWhenUnavailable(t *testing.T) {
	t.Parallel()

	_, err := Scan(context.Background(), ScanOptions{
		ImageTarget: "definitely.invalid.example/nonexistent:latest",
		Format:      FormatXSPDXJSON,
	})
	if err == nil {
		t.Fatal("expected image reference error")
	}
	if got := err.Error(); !strings.Contains(got, "containerd:") {
		t.Fatalf("expected containerd backend diagnostics in error, got: %v", err)
	}
}

func mustNewTestImage(t *testing.T) v1.Image {
	t.Helper()

	return mustNewTaggedTestImage(t, "demo", "1.0.0")
}

func mustNewTaggedTestImage(t *testing.T, name, version string) v1.Image {
	t.Helper()

	layer := static.NewLayer(buildTarLayer(t, map[string]string{
		"package.json": fmt.Sprintf(`{"name":"%s","version":"%s"}`, name, version),
	}), types.OCILayer)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append test layer failed: %v", err)
	}
	return img
}

func mustTag(t *testing.T, ref string) name.Tag {
	t.Helper()

	tag, err := name.NewTag(ref)
	if err != nil {
		t.Fatalf("parse tag failed: %v", err)
	}
	return tag
}

func verifySBOMPayloadHasNoRiskFields(t *testing.T, payload any) {
	t.Helper()

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}
	for _, key := range []string{"risk_score", "risk_level", "risk_assessment", "local_analysis", "cloud_analysis"} {
		if _, ok := doc[key]; ok {
			t.Fatalf("unexpected risk field %q in sbom payload", key)
		}
	}
}

func buildTarLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "layer.tar")
	if err := writeTarArchive(tarPath, files); err != nil {
		t.Fatalf("write layer tar failed: %v", err)
	}
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatalf("read layer tar failed: %v", err)
	}
	return data
}

func writeTarArchive(path string, files map[string]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	writer := tar.NewWriter(file)
	defer func() { _ = writer.Close() }()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}
		if err := writer.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := writer.Write([]byte(content)); err != nil {
			return err
		}
	}
	return nil
}
