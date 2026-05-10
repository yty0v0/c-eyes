package sbom

import (
	"context"

	"edrsystem/internal/sbom/imagebackend"
)

type resolvedScanRoot struct {
	rootPath string
	mode     imagebackend.TargetMode
	cleanup  func()
}

func resolveScanRoot(options ScanOptions) (*resolvedScanRoot, error) {
	resolved, err := imagebackend.Resolve(context.Background(), imagebackend.ResolveOptions{
		Path:        options.Path,
		ImageTarget: options.ImageTarget,
		TargetType:  options.TargetType,
	}, imagebackend.DefaultBackends(context.Background()))
	if err != nil {
		return nil, err
	}
	return &resolvedScanRoot{
		rootPath: resolved.RootPath,
		mode:     resolved.Mode,
		cleanup:  resolved.Cleanup,
	}, nil
}
