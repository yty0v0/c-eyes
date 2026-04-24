package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"edrsystem/internal/sbom/config"
	sbominventory "edrsystem/internal/sbom/inventory/sbom"
	"edrsystem/internal/sbom/spec"
)

const (
	FormatXSPDXJSON = "xspdx-json"
	FormatSPDXJSON  = "spdx-json"
)

var supportedFormats = map[string]struct{}{
	FormatXSPDXJSON: {},
	FormatSPDXJSON:  {},
}

type ScanOptions struct {
	Path   string
	Format string
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

func Scan(ctx context.Context, options ScanOptions) (any, error) {
	_ = ctx

	format, err := NormalizeFormat(options.Format)
	if err != nil {
		return nil, err
	}

	scanPath := strings.TrimSpace(options.Path)
	if scanPath == "" {
		cwd, cwdErr := os.Getwd()
		if cwdErr != nil {
			return nil, fmt.Errorf("resolve default scan path failed: %w", cwdErr)
		}
		scanPath = cwd
	}
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return nil, fmt.Errorf("resolve scan path failed: %w", err)
	}

	cfg := &config.GenerateConfig{
		SourceConfig: config.SourceConfig{
			SrcPath:     absPath,
			Parallelism: config.DefaultParallelism,
		},
		PackageConfig: config.PackageConfig{
			Path:        absPath,
			Parallelism: config.DefaultParallelism,
			Collectors:  "*",
		},
		ArtifactConfig: config.ArtifactConfig{
			DistPath:    absPath,
			Parallelism: config.DefaultParallelism,
		},
		AssemblyConfig: config.AssemblyConfig{
			Format: format,
		},
		Path:         absPath,
		NamespaceURI: defaultNamespaceURI(),
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
