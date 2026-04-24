package filescan

import (
	"context"

	"edrsystem/internal/processscan"
)

// ProcessCollector collects active process executables as scan targets.
type ProcessCollector struct{}

func (ProcessCollector) Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error) {
	procs, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
	if err != nil {
		return nil, err
	}
	tasks := make([]ScanTask, 0, len(procs))
	for _, proc := range procs {
		if proc.Path == nil || *proc.Path == "" {
			continue
		}
		tasks = append(tasks, ScanTask{
			Path:   *proc.Path,
			Source: SourceProcess,
			Mode:   ScanModeSmart,
		})
		if proc.PID != nil {
			modules, err := collectProcessModules(*proc.PID)
			if err == nil {
				for _, mod := range modules {
					if mod == "" {
						continue
					}
					tasks = append(tasks, ScanTask{
						Path:   mod,
						Source: SourceModule,
						Mode:   ScanModeSmart,
					})
				}
			}
		}
	}
	return dedupeTasks(tasks), nil
}
