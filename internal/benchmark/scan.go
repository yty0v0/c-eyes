package benchmark

import (
	"context"
	"fmt"
	"strings"
)

const benchmarkProgressTotalSteps = 100

const (
	benchmarkProgressAfterResolve   = 8
	benchmarkProgressAfterPrivilege = 16
	benchmarkProgressAfterPrepare   = 22
	benchmarkProgressExecuteStart   = benchmarkProgressAfterPrepare
	benchmarkProgressExecuteEnd     = 86
	benchmarkProgressCollectDone    = 93
	benchmarkProgressParseStart     = benchmarkProgressCollectDone
	benchmarkProgressParseEnd       = 99
)

func notifyProgress(progress func(done, total int, stage string), done, total int, stage string) {
	if progress == nil {
		return
	}
	progress(done, total, stage)
}

func benchmarkRangedProgress(start, end, done, total int) int {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	if total <= 0 {
		return start
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	if done == 0 {
		return start
	}
	span := end - start
	if span <= 0 {
		return end
	}
	return start + int(float64(done)/float64(total)*float64(span))
}

func benchmarkCollectorCommand(template Template, checkID, fallback string) string {
	fallback = strings.TrimSpace(fallback)
	if strings.HasPrefix(fallback, "native/") {
		return fallback
	}
	if strings.TrimSpace(checkID) == "" {
		return fallback
	}
	return fmt.Sprintf("native/%s/%s", template, checkID)
}

func Scan(ctx context.Context, options ScanOptions) (ScanResult, error) {
	progress := options.Progress
	notifyProgress(progress, 0, benchmarkProgressTotalSteps, "resolve template")

	selected := options.Template
	if selected == "" {
		selected = TemplateAuto
	}
	level := options.BaselineLevel
	if level == "" {
		level = BaselineLevel1
	}

	selectedTemplate, err := resolveTemplate(selected)
	if err != nil {
		return ScanResult{}, err
	}

	notifyProgress(progress, benchmarkProgressAfterResolve, benchmarkProgressTotalSteps, "check privilege")
	if err := ensureElevatedPrivilege(); err != nil {
		return ScanResult{}, err
	}
	notifyProgress(progress, benchmarkProgressAfterPrivilege, benchmarkProgressTotalSteps, "prepare checks")

	notifyProgress(progress, benchmarkProgressAfterPrepare, benchmarkProgressTotalSteps, "execute checks")
	if result, handled, err := scanWindowsNativeBenchmark(ctx, selectedTemplate, level, "", progress); handled {
		if err != nil {
			return ScanResult{}, err
		}
		notifyProgress(progress, benchmarkProgressTotalSteps, benchmarkProgressTotalSteps, "scan completed")
		return result, nil
	}
	if result, handled, err := scanUnixNativeBenchmark(ctx, selectedTemplate, level, "", progress); handled {
		if err != nil {
			return ScanResult{}, err
		}
		notifyProgress(progress, benchmarkProgressTotalSteps, benchmarkProgressTotalSteps, "scan completed")
		return result, nil
	}
	return ScanResult{}, fmt.Errorf("invalid argument: no native benchmark collector for template %s", selectedTemplate)
}
