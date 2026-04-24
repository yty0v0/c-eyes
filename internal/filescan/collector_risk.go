package filescan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
)

// HighRiskCollector scans high-risk directories for candidates.
type HighRiskCollector struct{}

func (HighRiskCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	_ = ctx
	dirs := highRiskDirs()
	if len(dirs) == 0 {
		return nil, nil
	}
	limit := normalizeSmartMaxTargets(params.MaxTargets)
	perDir := limit
	if len(dirs) > 0 {
		perDir = limit / len(dirs)
		if perDir <= 0 {
			perDir = 1
		}
	}
	var tasks []ScanTask
	for _, dir := range dirs {
		collected, err := collectFiles(dir, ScanModeSmart, SourceHighRisk, perDir, nil, params.OnTaskError)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, collected...)
	}
	return dedupeTasks(tasks), nil
}

func highRiskDirs() []string {
	var dirs []string
	if runtime.GOOS == "windows" {
		if user := os.Getenv("USERPROFILE"); user != "" {
			dirs = append(dirs, filepath.Join(user, "Downloads"))
		}
		if temp := os.Getenv("TEMP"); temp != "" {
			dirs = append(dirs, temp)
		}
		if appData := os.Getenv("APPDATA"); appData != "" {
			dirs = append(dirs, appData)
		}
		if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
			dirs = append(dirs, localApp)
		}
		if systemDrive := os.Getenv("SystemDrive"); systemDrive != "" {
			dirs = append(dirs, filepath.Join(systemDrive, "$Recycle.Bin"))
		}
		return dirs
	}

	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Downloads"))
		dirs = append(dirs, filepath.Join(home, ".cache"))
	}
	dirs = append(dirs, "/tmp", "/var/tmp")
	return dirs
}
