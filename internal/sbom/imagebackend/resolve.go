package imagebackend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func Resolve(ctx context.Context, options ResolveOptions, backends []ImageBackend) (*ResolvedTarget, error) {
	path := strings.TrimSpace(options.Path)
	if path != "" {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve scan path failed: %w", err)
		}
		return &ResolvedTarget{
			RootPath: absPath,
			Mode:     TargetModePath,
		}, nil
	}

	imageTarget := strings.TrimSpace(options.ImageTarget)
	if imageTarget != "" {
		mode, normalizedTarget, err := resolveImageTargetMode(imageTarget, strings.TrimSpace(options.TargetType))
		if err != nil {
			return nil, err
		}

		var img v1.Image
		switch mode {
		case TargetModeImageArchive:
			img, err = imageFromArchive(normalizedTarget)
		case TargetModeOCILayout:
			img, err = imageFromOCILayout(normalizedTarget)
		case TargetModeImage:
			img, err = imageFromReference(ctx, normalizedTarget, backends)
		default:
			err = fmt.Errorf("unsupported sbom image target mode: %s", mode)
		}
		if err != nil {
			return nil, err
		}
		rootPath, cleanup, err := ExtractImageToTempRoot(img)
		if err != nil {
			return nil, err
		}
		return &ResolvedTarget{
			RootPath: rootPath,
			Mode:     mode,
			Cleanup:  cleanup,
		}, nil
	}

	return nil, fmt.Errorf("sbom requires one target")
}

func resolveImageTargetMode(imageTarget, targetType string) (TargetMode, string, error) {
	switch targetType {
	case "", "auto":
		return autoDetectImageTargetMode(imageTarget)
	case "image":
		return TargetModeImage, imageTarget, nil
	case "archive":
		return TargetModeImageArchive, imageTarget, nil
	case "oci-layout":
		return TargetModeOCILayout, imageTarget, nil
	default:
		return "", "", fmt.Errorf("invalid argument: --target-type only supports auto|image|archive|oci-layout")
	}
}

func autoDetectImageTargetMode(imageTarget string) (TargetMode, string, error) {
	trimmed := strings.TrimSpace(imageTarget)
	if trimmed == "" {
		return "", "", fmt.Errorf("invalid argument: --image-target requires a value")
	}

	if existingMode, normalizedTarget, ok, err := detectExistingImageTarget(trimmed); ok || err != nil {
		return existingMode, normalizedTarget, err
	}

	if looksLikeLocalPath(trimmed) {
		return "", "", fmt.Errorf("image target path does not exist: %s", trimmed)
	}
	return TargetModeImage, trimmed, nil
}

func detectExistingImageTarget(value string) (TargetMode, string, bool, error) {
	layoutPath, layoutRef := splitOCILayoutSelector(value)
	if stat, err := os.Stat(layoutPath); err == nil {
		if stat.IsDir() {
			if isOCILayoutDir(layoutPath) {
				if layoutRef != "" {
					return TargetModeOCILayout, layoutPath + layoutRef, true, nil
				}
				return TargetModeOCILayout, layoutPath, true, nil
			}
			return "", "", true, fmt.Errorf("image target directory is not a valid OCI layout: %s", layoutPath)
		}
		return TargetModeImageArchive, value, true, nil
	} else if !os.IsNotExist(err) {
		return "", "", true, fmt.Errorf("stat image target failed: %w", err)
	}
	return "", "", false, nil
}

func splitOCILayoutSelector(value string) (string, string) {
	trimmed := strings.TrimSpace(value)
	prefix, rest := splitWindowsDrivePrefix(trimmed)
	if idx := strings.LastIndex(rest, "@"); idx >= 0 {
		return prefix + rest[:idx], rest[idx:]
	}
	if idx := strings.LastIndex(rest, ":"); idx >= 0 {
		candidate := prefix + rest[:idx]
		if candidate != "" {
			return candidate, rest[idx:]
		}
	}
	return trimmed, ""
}

func isOCILayoutDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "oci-layout")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "index.json")); err != nil {
		return false
	}
	return true
}

func looksLikeLocalPath(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, string(filepath.Separator)) {
		return true
	}
	if strings.Contains(trimmed, `\`) {
		return true
	}
	if len(trimmed) >= 2 && trimmed[1] == ':' {
		return true
	}
	return false
}

func imageFromArchive(archivePath string) (v1.Image, error) {
	absArchivePath, err := filepath.Abs(strings.TrimSpace(archivePath))
	if err != nil {
		return nil, fmt.Errorf("resolve image archive path failed: %w", err)
	}
	img, err := tarball.ImageFromPath(absArchivePath, nil)
	if err == nil {
		return img, nil
	}
	return nil, fmt.Errorf("load image archive failed: %w", err)
}

func imageFromOCILayout(layoutPath string) (v1.Image, error) {
	trimmed := strings.TrimSpace(layoutPath)
	prefix, rest := splitWindowsDrivePrefix(trimmed)
	inputFileName, inputRef, found := strings.Cut(rest, "@")
	if !found {
		inputFileName, inputRef, found = strings.Cut(rest, ":")
	}
	if !found {
		inputFileName = rest
		inputRef = ""
	}
	inputFileName = prefix + inputFileName

	absLayoutPath, err := filepath.Abs(inputFileName)
	if err != nil {
		return nil, fmt.Errorf("resolve OCI layout path failed: %w", err)
	}
	lp, err := layout.FromPath(absLayoutPath)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout failed: %w", err)
	}
	idx, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("open OCI image index failed: %w", err)
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read OCI index manifest failed: %w", err)
	}
	if len(manifest.Manifests) == 0 {
		return nil, fmt.Errorf("OCI layout contains no image manifest")
	}
	return selectOCIImage(manifest, idx, inputRef)
}

func splitWindowsDrivePrefix(value string) (string, string) {
	if len(value) >= 2 && value[1] == ':' {
		return value[:2], value[2:]
	}
	return "", value
}

func selectOCIImage(m *v1.IndexManifest, index v1.ImageIndex, inputRef string) (v1.Image, error) {
	for _, manifest := range m.Manifests {
		tag := manifest.Annotations[ispec.AnnotationRefName]
		if inputRef == "" || tag == inputRef || manifest.Digest.String() == inputRef {
			h := manifest.Digest
			if manifest.MediaType.IsIndex() {
				childIndex, err := index.ImageIndex(h)
				if err != nil {
					return nil, fmt.Errorf("open OCI child index failed: %w", err)
				}
				childManifest, err := childIndex.IndexManifest()
				if err != nil {
					return nil, fmt.Errorf("read OCI child manifest failed: %w", err)
				}
				return selectOCIImage(childManifest, childIndex, "")
			}
			img, err := index.Image(h)
			if err != nil {
				return nil, fmt.Errorf("open OCI image failed: %w", err)
			}
			return img, nil
		}
	}
	return nil, fmt.Errorf("invalid OCI image ref")
}

func imageFromReference(ctx context.Context, imageRef string, backends []ImageBackend) (v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference failed: %w", err)
	}

	var backendErrs []string
	for _, backend := range backends {
		img, err := backend.LoadImage(ref.Name())
		if err == nil {
			return img, nil
		}
		backendErrs = append(backendErrs, backend.Name()+": "+err.Error())
	}

	img, err := remote.Image(ref)
	if err == nil {
		return img, nil
	}
	backendErrs = append(backendErrs, "remote: "+err.Error())
	return nil, fmt.Errorf("native image collection is not available for image reference %q in this environment (%s)", imageRef, strings.Join(backendErrs, "; "))
}
