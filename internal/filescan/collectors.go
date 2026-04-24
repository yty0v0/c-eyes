package filescan

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
)

const (
	SourceProcess     = "process"
	SourceModule      = "module"
	SourcePersistence = "persistence"
	SourceHighRisk    = "high-risk"
	SourceRecent      = "recent"
	SourcePath        = "path"
	SourceFull        = "full"
	SourceEvent       = "event"
)

const defaultSmartMaxTargets = 10000

var errStopWalk = errors.New("stop walk")
var walkDirFn = filepath.WalkDir

// CompositeCollector merges multiple collectors.
type CompositeCollector struct {
	Collectors []TargetCollector
}

func (c CompositeCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	if len(c.Collectors) == 0 {
		return nil, nil
	}
	var all []ScanTask
	for _, collector := range c.Collectors {
		if collector == nil {
			continue
		}
		tasks, err := collector.Collect(ctx, params)
		if err != nil {
			return nil, err
		}
		all = append(all, tasks...)
	}
	deduped := dedupeTasks(all)
	if params.MaxTargets > 0 && len(deduped) > params.MaxTargets {
		return deduped[:params.MaxTargets], nil
	}
	return deduped, nil
}

func normalizeSmartMaxTargets(value int) int {
	if value <= 0 {
		return defaultSmartMaxTargets
	}
	return value
}

func dedupeTasks(tasks []ScanTask) []ScanTask {
	seen := make(map[string]struct{}, len(tasks))
	out := make([]ScanTask, 0, len(tasks))
	for _, task := range tasks {
		if task.Path == "" {
			continue
		}
		if _, ok := seen[task.Path]; ok {
			continue
		}
		seen[task.Path] = struct{}{}
		out = append(out, task)
	}
	return out
}

func collectFiles(root string, mode ScanMode, source string, maxTargets int, include func(path string, info fs.FileInfo) bool, onTaskError TaskErrorFunc) ([]ScanTask, error) {
	if root == "" {
		return nil, nil
	}
	limit := maxTargets
	tasks := make([]ScanTask, 0, 128)
	walkErr := walkDirFn(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if onTaskError != nil {
				onTaskError(ScanTask{
					Path:   path,
					Source: source,
					Mode:   mode,
				}, "collect_targets", err)
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if onTaskError != nil {
				onTaskError(ScanTask{
					Path:   path,
					Source: source,
					Mode:   mode,
				}, "collect_targets", err)
			}
			return nil
		}
		if include != nil && !include(path, info) {
			return nil
		}
		tasks = append(tasks, ScanTask{
			Path:   path,
			Source: source,
			Mode:   mode,
		})
		if limit > 0 && len(tasks) >= limit {
			return errStopWalk
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, errStopWalk) {
		return tasks, walkErr
	}
	return tasks, nil
}
