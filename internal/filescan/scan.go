package filescan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"edrsystem/internal/processscan"
)

var pathScanReadDirProbe = func(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	_, err = dir.Readdirnames(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// Scan performs a file scan based on params.
func Scan(ctx context.Context, params FileScanParams) ([]FileScanResult, error) {
	if params.Mode == "" {
		params.Mode = ScanModeFull
	}

	cache, _ := NewSQLiteCacheStore(DefaultCachePath())
	if cache != nil {
		defer cache.Close()
	}

	hostname, _ := os.Hostname()
	host, _ := processscan.GetHostInfo()
	filter := &DefaultFilterEngine{
		Cache:      cache,
		Signature:  DefaultSignatureVerifier{},
		Reputation: NoopReputationClient{},
		Hostname:   hostname,
		Host:       host,
	}
	deep := ThrottledDeepScanner{Inner: RuleDeepScanner{}}
	reporter := &DefaultResultReporter{Cache: cache}

	var tasks []ScanTask
	var err error

	switch params.Mode {
	case ScanModeFull:
		collectParams := params
		if params.SmartEnabled {
			collectParams.MaxTargets = 0
		}
		tasks, err = collectFullTargets(collectParams)
	case ScanModePath:
		if params.Path == "" {
			return nil, errors.New("path is required for path scan")
		}
		collectParams := params
		if params.SmartEnabled {
			collectParams.MaxTargets = 0
		}
		tasks, err = collectPathTargets(params.Path, collectParams)
	case ScanModeSmart:
		params.SmartEnabled = true
		tasks, err = collectSmartTargets(ctx, params)
	default:
		return nil, errors.New("invalid scan mode")
	}
	if err != nil {
		return nil, err
	}
	if params.SmartEnabled && params.Mode != ScanModeSmart {
		tasks = selectSmartSubset(tasks, params)
	}

	if params.Progress != nil {
		params.Progress(0, len(tasks), "collect_targets")
	}
	results, err := RunPipelineWithProgressAndOptions(
		ctx,
		tasks,
		filter,
		deep,
		reporter,
		params.Progress,
		PipelineExecutionOptions{
			Workers:     params.Workers,
			Mode:        params.Mode,
			OnTaskError: params.OnTaskError,
		},
	)
	if err != nil {
		return nil, err
	}
	for i := range results {
		results[i].SmartEnabled = boolPtr(params.SmartEnabled)
	}
	return results, nil
}

func collectFullTargets(params FileScanParams) ([]ScanTask, error) {
	roots := listRoots()
	if len(roots) == 0 {
		return nil, nil
	}
	perRoot := 0
	if params.MaxTargets > 0 {
		perRoot = params.MaxTargets / len(roots)
		if perRoot <= 0 {
			perRoot = 1
		}
	}
	var tasks []ScanTask
	for _, root := range roots {
		collected, err := collectFiles(root, ScanModeFull, SourceFull, perRoot, nil, params.OnTaskError)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, collected...)
	}
	return dedupeTasks(tasks), nil
}

func collectPathTargets(path string, params FileScanParams) ([]ScanTask, error) {
	if err := ensurePathScanRootAccessible(path); err != nil {
		if isPermissionDeniedError(err) {
			return nil, fmt.Errorf("scan path access is denied: %s", path)
		}
		return nil, err
	}
	tasks, err := collectFiles(path, ScanModePath, SourcePath, params.MaxTargets, nil, params.OnTaskError)
	if err != nil {
		return nil, err
	}
	return dedupeTasks(tasks), nil
}

func ensurePathScanRootAccessible(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return pathScanReadDirProbe(path)
}

func collectSmartTargets(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	if params.MaxTargets <= 0 {
		params.MaxTargets = defaultSmartMaxTargets
	}
	collector := CompositeCollector{
		Collectors: []TargetCollector{
			ProcessCollector{},
			PersistenceCollector{},
			HighRiskCollector{},
			RecentChangeCollector{},
		},
	}
	return collector.Collect(ctx, params)
}
