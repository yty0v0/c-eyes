package riskanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type stubUploadCloudClient struct {
	queryAnalysis CloudAnalysis
	queryScore    float64
	queryErr      error

	uploadTasks []CloudUploadTask
	uploadErr   error
	uploadCalls int
}

func (s *stubUploadCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return s.queryAnalysis, s.queryScore, s.queryErr
}

func (s *stubUploadCloudClient) Upload(ctx context.Context, req CloudUploadRequest) ([]CloudUploadTask, error) {
	s.uploadCalls++
	return append([]CloudUploadTask{}, s.uploadTasks...), s.uploadErr
}

func TestAnalyzerUploadAttemptWhenUnresolved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{
			CloudQueried:  true,
			CloudProvider: "virustotal",
		},
		queryScore: 10,
		uploadTasks: []CloudUploadTask{
			{
				Provider: "virustotal",
				Status:   CloudUploadStatusCompleted,
				TaskID:   "vt-task-1",
				Score:    92,
			},
		},
	}

	analyzer := Analyzer{
		Cloud:                    cloud,
		LocalWeight:              0.6,
		CloudWeight:              0.4,
		CloudUploadEnabled:       true,
		CloudUploadConcurrency:   2,
		CloudUploadPollInterval:  100 * time.Millisecond,
		CloudUploadSubmitTimeout: 2 * time.Second,
		CloudUploadWait:          2 * time.Second,
		CloudUploadMaxSize:       1024 * 1024,
	}

	results, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
	}, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if cloud.uploadCalls != 1 {
		t.Fatalf("expected one upload call, got %d", cloud.uploadCalls)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	result := results[0]
	if !result.CloudUploadEnabled {
		t.Fatalf("expected cloud_upload_enabled=true")
	}
	if !result.CloudUploadAttempted {
		t.Fatalf("expected cloud_upload_attempted=true")
	}
	if result.CloudUploadStatus != CloudUploadStatusCompleted {
		t.Fatalf("expected completed upload, got %s", result.CloudUploadStatus)
	}
	if result.RiskAssessment.RiskLevel != RiskLevelHigh {
		t.Fatalf("expected high risk after upload evidence, got %s", result.RiskAssessment.RiskLevel)
	}
}

func TestAnalyzerUploadBlockedByHighConfidenceCloud(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{
			CloudQueried: true,
		},
		queryScore: 85,
	}
	analyzer := Analyzer{
		Cloud:                   cloud,
		LocalWeight:             0.6,
		CloudWeight:             0.4,
		CloudUploadEnabled:      true,
		CloudUploadMaxSize:      1024 * 1024,
		CloudUploadWait:         time.Second,
		CloudUploadPollInterval: time.Second,
	}

	results, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			},
		},
	}, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if cloud.uploadCalls != 0 {
		t.Fatalf("expected zero upload calls, got %d", cloud.uploadCalls)
	}
	if got := results[0].CloudUploadStatus; got != CloudUploadStatusSkipped {
		t.Fatalf("expected skipped status, got %s", got)
	}
	if !strings.Contains(results[0].CloudUploadReason, "high-confidence") {
		t.Fatalf("unexpected upload skip reason: %s", results[0].CloudUploadReason)
	}
}

func TestAnalyzerUploadAttemptWhenCloudResultIsIneffective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{
			CloudQueried: false,
		},
		queryScore: 0,
		uploadTasks: []CloudUploadTask{
			{
				Provider: "virustotal",
				Status:   CloudUploadStatusCompleted,
				TaskID:   "vt-task-ineffective",
				Score:    40,
			},
		},
	}
	analyzer := Analyzer{
		Cloud:                   cloud,
		LocalWeight:             0.6,
		CloudWeight:             0.4,
		CloudUploadEnabled:      true,
		CloudUploadMaxSize:      1024 * 1024,
		CloudUploadWait:         time.Second,
		CloudUploadPollInterval: time.Second,
	}

	results, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": "1111111111111111111111111111111111111111111111111111111111111111",
				},
			},
		},
	}, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if cloud.uploadCalls != 1 {
		t.Fatalf("expected one upload call when cloud result is ineffective, got %d", cloud.uploadCalls)
	}
	if got := results[0].CloudUploadStatus; got != CloudUploadStatusCompleted {
		t.Fatalf("expected completed upload status, got %s", got)
	}
	if !results[0].CloudUploadAttempted {
		t.Fatalf("expected cloud_upload_attempted=true")
	}
}

func TestAnalyzerUploadEmitsWaitingProgress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{
			CloudQueried: false,
		},
		queryScore: 0,
		uploadTasks: []CloudUploadTask{
			{
				Provider: "virustotal",
				Status:   CloudUploadStatusPending,
				TaskID:   "vt-task-pending",
			},
		},
	}

	var (
		mu     sync.Mutex
		stages []string
	)
	analyzer := Analyzer{
		Cloud:                   cloud,
		CloudUploadEnabled:      true,
		CloudUploadMaxSize:      1024 * 1024,
		CloudUploadWait:         time.Second,
		CloudUploadPollInterval: time.Second,
		OnProgress: func(event ProgressEvent) {
			mu.Lock()
			stages = append(stages, event.Stage)
			mu.Unlock()
		},
	}

	_, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": "2222222222222222222222222222222222222222222222222222222222222222",
				},
			},
		},
	}, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	foundWaitingStage := false
	for _, stage := range stages {
		if stage == stageUploadWaiting {
			foundWaitingStage = true
			break
		}
	}
	if !foundWaitingStage {
		t.Fatalf("expected waiting stage progress, got %v", stages)
	}
}

func TestAnalyzerUploadFailedStatus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{
			CloudQueried: true,
		},
		queryScore: 10,
		uploadTasks: []CloudUploadTask{
			{
				Provider: "triage",
				Status:   CloudUploadStatusFailed,
				TaskID:   "triage-task",
				Error:    "submit timeout",
			},
		},
	}
	analyzer := Analyzer{
		Cloud:                   cloud,
		LocalWeight:             0.6,
		CloudWeight:             0.4,
		CloudUploadEnabled:      true,
		CloudUploadMaxSize:      1024 * 1024,
		CloudUploadWait:         time.Second,
		CloudUploadPollInterval: time.Second,
	}

	results, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
				},
			},
		},
	}, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].CloudUploadStatus; got != CloudUploadStatusFailed {
		t.Fatalf("expected failed upload status, got %s", got)
	}
	if results[0].CloudUploadReason == "" {
		t.Fatalf("expected upload failure reason")
	}
}

func TestAnalyzerHighRiskShortCircuitFromLocal(t *testing.T) {
	local := stubLocalMatcher{
		analysis: LocalAnalysis{
			LocalMatched: true,
			YaraResults: []YaraRuleMatch{
				{RuleName: "critical_rule", Severity: 95},
			},
		},
		score: 95,
	}
	cloud := &stubUploadCloudClient{
		queryAnalysis: CloudAnalysis{CloudQueried: false},
		queryScore:    0,
	}
	analyzer := Analyzer{
		Local: local,
		Cloud: cloud,
	}

	results, err := analyzer.Analyze(context.Background(), []ScanRecord{
		{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": "C:/tmp/critical.bin",
				"hashes": map[string]any{
					"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
				},
			},
		},
	}, ModeSmart)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].RiskAssessment.Stage; got != stageHighRiskShort {
		t.Fatalf("expected stage %s, got %s", stageHighRiskShort, got)
	}
	if got := results[0].RiskAssessment.RiskLevel; got != RiskLevelHigh {
		t.Fatalf("expected high risk, got %s", got)
	}
}

func TestAnalyzerAutoBudgetScalesWithNAndU(t *testing.T) {
	analyzer := Analyzer{CloudUploadEnabled: true}
	submit := 20 * time.Second
	wait := 60 * time.Second
	poll := 5 * time.Second

	small := analyzer.computeAutoBudget(ModeSmart, 1, 0, 2, submit, wait, poll)
	bigN := analyzer.computeAutoBudget(ModeSmart, 100, 0, 2, submit, wait, poll)
	if bigN <= small {
		t.Fatalf("expected budget to increase with N, small=%s big=%s", small, bigN)
	}
	bigU := analyzer.computeAutoBudget(ModeSmart, 100, 50, 2, submit, wait, poll)
	if bigU <= bigN {
		t.Fatalf("expected upload budget to increase with U, no-upload=%s upload=%s", bigN, bigU)
	}
}

func TestUploadWaitDefaultsByMode(t *testing.T) {
	analyzer := Analyzer{}
	if got := analyzer.uploadWait(ModeFast); got != 10*time.Second {
		t.Fatalf("expected fast wait 10s, got %s", got)
	}
	if got := analyzer.uploadWait(ModeSmart); got != 3*time.Minute {
		t.Fatalf("expected smart wait 3m, got %s", got)
	}
	if got := analyzer.uploadWait(ModeCloudOnly); got != 4*time.Minute {
		t.Fatalf("expected cloud_only wait 4m, got %s", got)
	}
	if got := analyzer.uploadWait(ModeDeep); got != 6*time.Minute {
		t.Fatalf("expected deep wait 6m, got %s", got)
	}
}
