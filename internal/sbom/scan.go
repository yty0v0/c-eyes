package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"edrsystem/internal/sbom/config"
	"edrsystem/internal/sbom/imagebackend"
	sbominventory "edrsystem/internal/sbom/inventory/sbom"
	"edrsystem/internal/sbom/spec"
)

const (
	FormatXSPDXJSON     = "xspdx-json"
	FormatSPDXJSON      = "spdx-json"
	TargetTypeAuto      = "auto"
	TargetTypeImage     = "image"
	TargetTypeArchive   = "archive"
	TargetTypeOCILayout = "oci-layout"
)

var supportedFormats = map[string]struct{}{
	FormatXSPDXJSON: {},
	FormatSPDXJSON:  {},
}

var supportedTargetTypes = map[string]struct{}{
	TargetTypeAuto:      {},
	TargetTypeImage:     {},
	TargetTypeArchive:   {},
	TargetTypeOCILayout: {},
}

type ScanOptions struct {
	Path        string
	ImageTarget string
	TargetType  string
	Format      string
}

func IsSupportedFormat(value string) bool {
	_, ok := supportedFormats[strings.TrimSpace(value)]
	return ok
}

func NormalizeFormat(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return FormatXSPDXJSON, nil
	}
	if !IsSupportedFormat(trimmed) {
		return "", fmt.Errorf("invalid argument: --format only supports xspdx-json|spdx-json")
	}
	return trimmed, nil
}

func NormalizeTargetType(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return TargetTypeAuto, nil
	}
	if _, ok := supportedTargetTypes[trimmed]; !ok {
		return "", fmt.Errorf("invalid argument: --target-type only supports auto|image|archive|oci-layout")
	}
	return trimmed, nil
}

func Scan(ctx context.Context, options ScanOptions) (any, error) {
	_ = ctx

	format, err := NormalizeFormat(options.Format)
	if err != nil {
		return nil, err
	}

	resolved, err := resolveScanRoot(options)
	if err != nil {
		return nil, err
	}
	if resolved.cleanup != nil {
		defer resolved.cleanup()
	}

	cfg := &config.GenerateConfig{
		SourceConfig: config.SourceConfig{
			SrcPath:     resolved.rootPath,
			Parallelism: config.DefaultParallelism,
		},
		PackageConfig: config.PackageConfig{
			Path:        resolved.rootPath,
			Parallelism: config.DefaultParallelism,
			Collectors:  "*",
		},
		ArtifactConfig: config.ArtifactConfig{
			DistPath:    resolved.rootPath,
			Parallelism: config.DefaultParallelism,
		},
		AssemblyConfig: config.AssemblyConfig{
			Format: format,
		},
		Path:         resolved.rootPath,
		NamespaceURI: defaultNamespaceURI(),
	}
	if resolved.mode != imagebackend.TargetModePath {
		cfg.SkipPhases = sbominventory.SourcePhase
	}

	doc, err := sbominventory.GenerateSBOM(cfg)
	if err != nil {
		return nil, err
	}

	sbomFormat := spec.GetFormat(format)
	if sbomFormat == nil {
		return nil, fmt.Errorf("invalid format: %s", format)
	}
	sbomFormat.Spec().FromModel(doc)

	var buf bytes.Buffer
	if err := sbomFormat.Dump(&buf); err != nil {
		return nil, fmt.Errorf("dump sbom failed: %w", err)
	}

	var payload any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("parse sbom payload failed: %w", err)
	}
	return payload, nil
}

func defaultNamespaceURI() string {
	return fmt.Sprintf("https://c-eyes.local/sbom/%d", time.Now().UnixNano())
}
