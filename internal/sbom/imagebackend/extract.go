package imagebackend

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

func ExtractImageToTempRoot(img v1.Image) (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "sbom-image-rootfs-")
	if err != nil {
		return "", nil, fmt.Errorf("create temp image root failed: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	rc := mutate.Extract(img)
	defer func() { _ = rc.Close() }()
	reader := tar.NewReader(rc)
	for {
		hdr, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("extract image layer failed: %w", err)
		}
		targetPath := filepath.Join(tmpDir, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(targetPath, tmpDir) {
			cleanup()
			return "", nil, fmt.Errorf("invalid image entry: %s", hdr.Name)
		}
		baseName := filepath.Base(hdr.Name)
		if strings.HasPrefix(baseName, ".wh.") {
			removeTarget := filepath.Join(filepath.Dir(targetPath), strings.TrimPrefix(baseName, ".wh."))
			_ = os.RemoveAll(removeTarget)
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("create image directory failed: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("prepare image file failed: %w", err)
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				cleanup()
				return "", nil, fmt.Errorf("create image file failed: %w", err)
			}
			if _, err := io.Copy(out, reader); err != nil {
				_ = out.Close()
				cleanup()
				return "", nil, fmt.Errorf("write image file failed: %w", err)
			}
			if err := out.Close(); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("close image file failed: %w", err)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("prepare image symlink failed: %w", err)
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(hdr.Linkname, targetPath); err != nil && runtime.GOOS != "windows" {
				cleanup()
				return "", nil, fmt.Errorf("create image symlink failed: %w", err)
			}
		case tar.TypeLink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("prepare image hardlink failed: %w", err)
			}
			linkTarget := filepath.Join(tmpDir, filepath.Clean(hdr.Linkname))
			_ = os.Remove(targetPath)
			if err := os.Link(linkTarget, targetPath); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("create image hardlink failed: %w", err)
			}
		}
	}
	return tmpDir, cleanup, nil
}
