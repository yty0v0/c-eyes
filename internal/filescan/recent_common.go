package filescan

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

var interestingExt = map[string]struct{}{
	".exe": {},
	".dll": {},
	".sys": {},
	".bat": {},
	".cmd": {},
	".ps1": {},
	".vbs": {},
	".js":  {},
	".jar": {},
	".sh":  {},
	".py":  {},
}

func isInterestingExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := interestingExt[ext]
	return ok
}

func collectRecentFallback(ctx context.Context, params FileScanParams, since time.Time) ([]ScanTask, error) {
	_ = ctx
	dirs := highRiskDirs()
	if len(dirs) == 0 {
		return nil, nil
	}
	limit := normalizeSmartMaxTargets(params.MaxTargets)
	perDir := limit / len(dirs)
	if perDir <= 0 {
		perDir = 1
	}

	var tasks []ScanTask
	for _, dir := range dirs {
		collected, err := collectFiles(dir, ScanModeSmart, SourceRecent, perDir, func(path string, info fs.FileInfo) bool {
			if !info.ModTime().After(since) {
				return false
			}
			return isInterestingExtension(path)
		}, params.OnTaskError)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, collected...)
	}
	return dedupeTasks(tasks), nil
}
