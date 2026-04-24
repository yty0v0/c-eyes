package filescan

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

type stubFilter struct {
	calls int32
}

func (s *stubFilter) Filter(ctx context.Context, task ScanTask) (FilterDecision, error) {
	atomic.AddInt32(&s.calls, 1)
	result := FileScanResult{
		ScanMode: scanModePtr(task.Mode),
		Source:   strPtr(task.Source),
		BasicInfo: &FileBasicInfo{
			FilePath: strPtr(task.Path),
		},
	}
	return FilterDecision{Result: result, Final: false}, nil
}

type stubDeep struct {
	calls int32
}

func (s *stubDeep) Scan(ctx context.Context, task ScanTask) (DeepScanResult, error) {
	atomic.AddInt32(&s.calls, 1)
	return DeepScanResult{Result: ScanResultSafe}, nil
}

type selectiveErrorDeep struct{}

func (selectiveErrorDeep) Scan(ctx context.Context, task ScanTask) (DeepScanResult, error) {
	if strings.Contains(task.Path, "deny") {
		return DeepScanResult{}, errors.New("access is denied")
	}
	return DeepScanResult{Result: ScanResultSafe}, nil
}

type stubReporter struct {
	calls int32
}

func (s *stubReporter) Report(ctx context.Context, result FileScanResult) (FileScanResult, error) {
	atomic.AddInt32(&s.calls, 1)
	return result, nil
}

func TestRunPipeline_DeepScanPath(t *testing.T) {
	filter := &stubFilter{}
	deep := &stubDeep{}
	reporter := &stubReporter{}

	task := ScanTask{Path: "/tmp/a", Source: SourcePath, Mode: ScanModePath}
	results, err := RunPipeline(context.Background(), []ScanTask{task}, filter, deep, reporter)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if got := atomic.LoadInt32(&deep.calls); got != 1 {
		t.Fatalf("expected deep scan called once, got %d", got)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result")
	}
	if results[0].ScanResult == nil || *results[0].ScanResult != ScanResultSafe {
		t.Fatalf("expected safe result from deep scan")
	}
}

func TestRunPipeline_AdaptiveWorkersCompletes(t *testing.T) {
	filter := &stubFilter{}
	deep := &stubDeep{}
	reporter := &stubReporter{}

	tasks := make([]ScanTask, 0, 128)
	for i := 0; i < 128; i++ {
		tasks = append(tasks, ScanTask{Path: "/tmp/a", Source: SourcePath, Mode: ScanModePath})
	}

	results, err := RunPipelineWithProgressAndOptions(
		context.Background(),
		tasks,
		filter,
		deep,
		reporter,
		nil,
		PipelineExecutionOptions{},
	)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if len(results) != len(tasks) {
		t.Fatalf("expected %d results, got %d", len(tasks), len(results))
	}
}

func TestRunPipeline_TaskErrorSkipsFailedTaskAndContinues(t *testing.T) {
	filter := &stubFilter{}
	deep := selectiveErrorDeep{}
	reporter := &stubReporter{}

	tasks := []ScanTask{
		{Path: "/tmp/ok-a", Source: SourcePath, Mode: ScanModePath},
		{Path: "/tmp/deny-b", Source: SourcePath, Mode: ScanModePath},
		{Path: "/tmp/ok-c", Source: SourcePath, Mode: ScanModePath},
	}

	var failed atomic.Int32
	var lastStage string
	var lastPath string

	results, err := RunPipelineWithProgressAndOptions(
		context.Background(),
		tasks,
		filter,
		deep,
		reporter,
		nil,
		PipelineExecutionOptions{
			OnTaskError: func(task ScanTask, stage string, err error) {
				failed.Add(1)
				lastStage = stage
				lastPath = task.Path
			},
		},
	)
	if err != nil {
		t.Fatalf("pipeline error: %v", err)
	}
	if got := failed.Load(); got != 1 {
		t.Fatalf("expected 1 failed task callback, got %d", got)
	}
	if lastStage != "deep_scan" {
		t.Fatalf("expected failed stage deep_scan, got %q", lastStage)
	}
	if !strings.Contains(lastPath, "deny-b") {
		t.Fatalf("expected deny task path in callback, got %q", lastPath)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 successful results, got %d", len(results))
	}
}

func TestResolvePipelineWorkerProfile_PathModeScalesUpForLargeBacklog(t *testing.T) {
	t.Setenv("C_EYES_FILESCAN_WORKERS", "")
	t.Setenv("C_EYES_FILESCAN_WORKERS_MIN", "")
	t.Setenv("C_EYES_FILESCAN_WORKERS_MAX", "")
	t.Setenv("C_EYES_FILESCAN_MEM_HIGH_MIB", "")
	t.Setenv("C_EYES_FILESCAN_MEM_LOW_MIB", "")

	original := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(original)

	profile := resolvePipelineWorkerProfile(3000, PipelineExecutionOptions{Mode: ScanModePath})
	if profile.initial < 3 {
		t.Fatalf("expected path mode initial workers >= 3 for large backlog, got %d", profile.initial)
	}
	if profile.max < 6 {
		t.Fatalf("expected path mode max workers >= 6 for large backlog, got %d", profile.max)
	}
}

func TestResolvePipelineWorkerProfile_SmartModeStaysConservative(t *testing.T) {
	t.Setenv("C_EYES_FILESCAN_WORKERS", "")
	t.Setenv("C_EYES_FILESCAN_WORKERS_MIN", "")
	t.Setenv("C_EYES_FILESCAN_WORKERS_MAX", "")
	t.Setenv("C_EYES_FILESCAN_MEM_HIGH_MIB", "")
	t.Setenv("C_EYES_FILESCAN_MEM_LOW_MIB", "")

	original := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(original)

	profile := resolvePipelineWorkerProfile(3000, PipelineExecutionOptions{Mode: ScanModeSmart})
	if profile.max > 6 {
		t.Fatalf("expected smart mode max workers <= 6, got %d", profile.max)
	}
	if profile.initial > 3 {
		t.Fatalf("expected smart mode initial workers <= 3, got %d", profile.initial)
	}
}
