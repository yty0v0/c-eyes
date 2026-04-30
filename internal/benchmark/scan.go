package benchmark

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

func Scan(ctx context.Context, options ScanOptions) (ScanResult, error) {
	progress := options.Progress
	notifyProgress(progress, 0, benchmarkProgressTotalSteps, "resolve template")

	selected := options.Template
	if selected == "" {
		selected = TemplateAuto
	}

	selectedTemplate, err := resolveTemplate(selected)
	if err != nil {
		return ScanResult{}, err
	}

	notifyProgress(progress, benchmarkProgressAfterResolve, benchmarkProgressTotalSteps, "check privilege")
	if err := ensureElevatedPrivilege(); err != nil {
		return ScanResult{}, err
	}
	if err := ensureRuntimeDependencies(selectedTemplate); err != nil {
		return ScanResult{}, err
	}

	notifyProgress(progress, benchmarkProgressAfterPrivilege, benchmarkProgressTotalSteps, "prepare checks")
	workingRoot, err := os.MkdirTemp("", "c-eyes-benchmark-run-")
	if err != nil {
		return ScanResult{}, err
	}
	defer func() { _ = os.RemoveAll(workingRoot) }()

	notifyProgress(progress, benchmarkProgressAfterPrepare, benchmarkProgressTotalSteps, "execute checks")
	if result, handled, err := scanWindowsNativeBenchmark(ctx, selectedTemplate, workingRoot, progress); handled {
		if err != nil {
			return ScanResult{}, err
		}
		notifyProgress(progress, benchmarkProgressTotalSteps, benchmarkProgressTotalSteps, "scan completed")
		return result, nil
	}
	if result, handled, err := scanUnixNativeBenchmark(ctx, selectedTemplate, workingRoot, progress); handled {
		if err != nil {
			return ScanResult{}, err
		}
		notifyProgress(progress, benchmarkProgressTotalSteps, benchmarkProgressTotalSteps, "scan completed")
		return result, nil
	}

	generatedXML, err := runNativeTemplateChecks(ctx, selectedTemplate, workingRoot, progress)
	if err != nil {
		return ScanResult{}, err
	}

	notifyProgress(progress, benchmarkProgressParseStart, benchmarkProgressTotalSteps, "parse results")
	rows := make([]Row, 0, 256)
	parsedRows, err := parseXMLFile(generatedXML, selectedTemplate)
	if err != nil {
		return ScanResult{}, err
	}
	rows = append(rows, parsedRows...)
	summary := summarize(rows)
	notifyProgress(progress, benchmarkProgressParseEnd, benchmarkProgressTotalSteps, "finalize results")
	notifyProgress(progress, benchmarkProgressTotalSteps, benchmarkProgressTotalSteps, "scan completed")

	return ScanResult{
		Template: string(selectedTemplate),
		Summary:  summary,
		Rows:     rows,
	}, nil
}

func ensureRuntimeDependencies(template Template) error {
	missing := make([]string, 0, 2)
	for _, cmd := range requiredCommands(template) {
		if _, err := exec.LookPath(cmd); err != nil {
			missing = append(missing, cmd)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("benchmark requires runtime dependencies: %s", strings.Join(missing, ", "))
}

func requiredCommands(template Template) []string {
	if template == TemplateWindows {
		return []string{"cmd"}
	}
	return []string{"sh"}
}
