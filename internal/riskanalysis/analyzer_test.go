package riskanalysis

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubLocalMatcher struct {
	analysis LocalAnalysis
	score    float64
}

func (s stubLocalMatcher) Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error) {
	return s.analysis, s.score, nil
}

type stubCloudClient struct {
	analysis CloudAnalysis
	score    float64
	err      error
}

func (s stubCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return s.analysis, s.score, s.err
}

type countingCloudClient struct {
	calls int
}

func (c *countingCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	c.calls++
	return CloudAnalysis{CloudQueried: true, CloudProvider: "virustotal"}, 50, nil
}

type countingLocalMatcher struct {
	calls    int
	analysis LocalAnalysis
	score    float64
}

func (m *countingLocalMatcher) Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error) {
	m.calls++
	return m.analysis, m.score, nil
}

type pathErrorLocalMatcher struct {
	errorPath string
	analysis  LocalAnalysis
	score     float64
}

func (m pathErrorLocalMatcher) Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error) {
	if target.TargetPath == m.errorPath {
		return LocalAnalysis{}, 0, errors.New("local engine boom")
	}
	return m.analysis, m.score, nil
}

type stubWhitelistEngine struct {
	analysis WhitelistAnalysis
	calls    int
}

func (s *stubWhitelistEngine) Evaluate(ctx context.Context, meta TargetMetadata, record ScanRecord, stage string) (WhitelistAnalysis, error) {
	s.calls++
	return s.analysis, nil
}

func TestAnalyzerSmartAlias(t *testing.T) {
	records := []ScanRecord{
		{Raw: map[string]any{
			"basic_info": map[string]any{
				"file_path":       "C:/tmp/sample.bin",
				"file_size_bytes": 2048,
			},
			"hashes": map[string]any{
				"sha256": "abc",
			},
		}},
	}

	matches := []YaraRuleMatch{{RuleName: "rule", Severity: 90}}
	localAnalysis := LocalAnalysis{LocalMatched: true, YaraResults: matches}
	localScore := LocalScoreFromMatches(matches)

	cloudAnalysis := CloudAnalysis{
		CloudQueried:  true,
		Malicious:     34,
		TotalEngines:  70,
		DetectionRate: "34/70",
		ThreatLabels:  []string{"Trojan"},
		CloudLink:     "https://example.invalid",
	}
	cloudScore := CloudScoreFromAnalysis(cloudAnalysis)

	analyzer := Analyzer{
		Local:       stubLocalMatcher{analysis: localAnalysis, score: localScore},
		Cloud:       stubCloudClient{analysis: cloudAnalysis, score: cloudScore},
		LocalWeight: 0.6,
		CloudWeight: 0.4,
		Now: func() time.Time {
			return time.Date(2026, 3, 17, 13, 35, 0, 0, time.UTC)
		},
	}

	results, err := analyzer.Analyze(context.Background(), records, ModeHybrid)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	result := results[0]
	if result.RiskAssessment.AnalysisMode != ModeSmart {
		t.Fatalf("expected mode smart, got %s", result.RiskAssessment.AnalysisMode)
	}
	if result.RiskAssessment.RiskLevel != RiskLevelHigh {
		t.Fatalf("expected high risk, got %s", result.RiskAssessment.RiskLevel)
	}
	if result.LocalAnalysis == nil || !result.LocalAnalysis.LocalMatched {
		t.Fatalf("expected local match")
	}
	if result.CloudAnalysis != nil && result.CloudAnalysis.CloudQueried {
		t.Fatalf("expected smart mode high-confidence path to skip cloud query")
	}
}

func TestAnalyzerCloudError(t *testing.T) {
	records := []ScanRecord{{Raw: map[string]any{"hashes": map[string]any{"sha256": "abc"}}}}
	analyzer := Analyzer{
		Cloud:       stubCloudClient{err: errors.New("boom")},
		LocalWeight: 0.5,
		CloudWeight: 0.5,
	}

	results, err := analyzer.Analyze(context.Background(), records, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CloudAnalysis == nil || results[0].CloudAnalysis.CloudQueried {
		t.Fatalf("expected cloud_queried=false on error")
	}
}

func TestAnalyzerLocalOnlyRecordErrorFallsBackAndContinues(t *testing.T) {
	records := []ScanRecord{
		{Raw: map[string]any{
			"target_type": "file",
			"target_path": "C:/tmp/bad.bin",
			"hashes": map[string]any{
				"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		}},
		{Raw: map[string]any{
			"target_type": "file",
			"target_path": "C:/tmp/good.bin",
			"hashes": map[string]any{
				"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		}},
	}

	analyzer := Analyzer{
		Local: pathErrorLocalMatcher{
			errorPath: "C:/tmp/bad.bin",
			analysis: LocalAnalysis{
				LocalMatched: true,
				YaraResults: []YaraRuleMatch{
					{RuleName: "ok_rule", Severity: 70},
				},
			},
			score: 70,
		},
		LocalWeight: 1.0,
		CloudWeight: 0,
	}

	results, err := analyzer.Analyze(context.Background(), records, ModeLocalOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	first := results[0]
	if first.LocalAnalysis == nil || !first.LocalAnalysis.LocalFallback {
		t.Fatalf("expected first record local fallback")
	}
	if first.LocalAnalysis.LocalFallbackReason == "" {
		t.Fatalf("expected fallback reason for first record")
	}
	if first.RiskAssessment.Stage != stageLocalOnly {
		t.Fatalf("expected first stage %s, got %s", stageLocalOnly, first.RiskAssessment.Stage)
	}

	second := results[1]
	if second.LocalAnalysis == nil || !second.LocalAnalysis.LocalMatched {
		t.Fatalf("expected second record local matched result")
	}
	if second.RiskAssessment.RiskScore <= 0 {
		t.Fatalf("expected second record positive risk score, got %.2f", second.RiskAssessment.RiskScore)
	}
}

func TestAnalyzerSmartWhitelistSkipsCloud(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionAllow,
			Source:   "trusted_publisher",
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{
		{
			Raw: map[string]any{
				"target_type":     "file",
				"target_path":     "C:/tmp/signed.exe",
				"signature_valid": true,
				"hashes": map[string]any{
					"sha256": "abc",
				},
			},
		},
	}

	results, err := analyzer.Analyze(context.Background(), records, ModeSmart)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("expected cloud query skipped for whitelist, got %d calls", client.calls)
	}
	if local.calls != 0 {
		t.Fatalf("expected local matcher skipped for whitelist allow, got %d calls", local.calls)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].RiskAssessment.RiskScore != 0 {
		t.Fatalf("expected whitelist risk score 0, got %.2f", results[0].RiskAssessment.RiskScore)
	}
	if results[0].Whitelist == nil || results[0].Whitelist.Decision != WhitelistDecisionAllow {
		t.Fatalf("expected whitelist allow in output")
	}
}

func TestAnalyzerWhitelistDenyShortCircuitsDeep(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionDeny,
			Source:   "byovd_blocklist",
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/driver.sys",
		"hashes": map[string]any{
			"sha256": "abc",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeDeep)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("expected cloud query skipped for whitelist deny, got %d calls", client.calls)
	}
	if local.calls != 0 {
		t.Fatalf("expected local matcher skipped for whitelist deny, got %d calls", local.calls)
	}
	if got := results[0].RiskAssessment.RiskScore; got != 100 {
		t.Fatalf("expected deny risk score 100, got %.2f", got)
	}
}

func TestAnalyzerWhitelistContinueTriggersLocalAndCloud(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{
		analysis: LocalAnalysis{LocalMatched: false},
		score:    0,
	}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionContinue,
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/unknown.bin",
		"hashes": map[string]any{
			"sha256": "abc",
		},
	}}}

	_, err := analyzer.Analyze(context.Background(), records, ModeSmart)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if local.calls == 0 {
		t.Fatalf("expected local matcher to run on continue path")
	}
	if client.calls == 0 {
		t.Fatalf("expected cloud query to run on continue path")
	}
}

func TestAnalyzerFunnelOrderCacheHashSignatureThenCloud(t *testing.T) {
	valid := true
	policy := WhitelistPolicy{
		Version: "1",
		TrustedPublishers: []TrustedPublisherRule{
			{ID: "trusted-microsoft", Publisher: "microsoft", RequireValid: true},
		},
		NSRLHashes: []string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}
	policy.normalize()
	cache := NewLocalReputationCache(16, time.Hour)
	cache.Set("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", WhitelistDecisionAllow)
	repo, err := NewAuthorityHashRepo(&policy)
	if err != nil {
		t.Fatalf("NewAuthorityHashRepo error: %v", err)
	}
	wl := NewDefaultWhitelistEngine(&policy, repo, cache)
	client := &countingCloudClient{}
	local := &countingLocalMatcher{analysis: LocalAnalysis{}, score: 0}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}

	records := []ScanRecord{
		{Raw: map[string]any{"target_type": "file", "target_path": "C:/tmp/cache.bin", "hashes": map[string]any{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},
		{Raw: map[string]any{"target_type": "file", "target_path": "C:/tmp/nsrl.bin", "hashes": map[string]any{"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}},
		{Raw: map[string]any{"target_type": "file", "target_path": "C:/Windows/System32/notepad.exe", "signature_valid": true, "signer_subject": "Microsoft Corporation", "hashes": map[string]any{"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}},
		{Raw: map[string]any{"target_type": "file", "target_path": "C:/tmp/unknown.bin", "signature_valid": valid, "signer_subject": "Unknown Publisher", "hashes": map[string]any{"sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}},
	}
	results, err := analyzer.Analyze(context.Background(), records, ModeSmart)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	if results[0].Whitelist == nil || results[0].Whitelist.Source != "local_cache" {
		t.Fatalf("expected first record allow from local_cache")
	}
	if results[1].Whitelist == nil || results[1].Whitelist.Source != "nsrl" {
		t.Fatalf("expected second record allow from nsrl")
	}
	if results[2].Whitelist == nil || results[2].Whitelist.Source != "trusted_publisher" {
		t.Fatalf("expected third record allow from trusted_publisher")
	}
	if results[3].Whitelist == nil || results[3].Whitelist.Decision != WhitelistDecisionContinue {
		t.Fatalf("expected fourth record continue to analysis path")
	}
	if client.calls == 0 {
		t.Fatalf("expected cloud query for unknown sample in funnel")
	}
}

func TestAnalyzerFastWhitelistAllowShortCircuit(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionAllow,
			Source:   "local_cache",
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/cache.bin",
		"hashes": map[string]any{
			"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeFast)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if client.calls != 0 {
		t.Fatalf("expected fast allow to skip cloud, got %d calls", client.calls)
	}
	if local.calls != 0 {
		t.Fatalf("expected fast allow to skip local fallback, got %d calls", local.calls)
	}
	if got := results[0].RiskAssessment.RiskScore; got != 0 {
		t.Fatalf("expected risk score 0, got %.2f", got)
	}
	if got := results[0].RiskAssessment.Stage; got != stageFastWhitelist {
		t.Fatalf("expected stage %s, got %s", stageFastWhitelist, got)
	}
}

func TestAnalyzerFastWhitelistDenyShortCircuit(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionDeny,
			Source:   "byovd_blocklist",
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/driver.sys",
		"hashes": map[string]any{
			"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeFast)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if client.calls != 0 {
		t.Fatalf("expected fast deny to skip cloud, got %d calls", client.calls)
	}
	if local.calls != 0 {
		t.Fatalf("expected fast deny to skip local fallback, got %d calls", local.calls)
	}
	if got := results[0].RiskAssessment.RiskScore; got != 100 {
		t.Fatalf("expected risk score 100, got %.2f", got)
	}
	if got := results[0].RiskAssessment.Stage; got != stageFastWhitelist {
		t.Fatalf("expected stage %s, got %s", stageFastWhitelist, got)
	}
}

func TestAnalyzerFastWhitelistContinueRunsFallback(t *testing.T) {
	client := &countingCloudClient{}
	local := &countingLocalMatcher{
		analysis: LocalAnalysis{LocalMatched: false},
		score:    0,
	}
	wl := &stubWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionContinue,
			Source:   "whitelist_funnel",
		},
	}
	analyzer := Analyzer{
		Cloud:     client,
		Local:     local,
		Whitelist: wl,
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/unknown.bin",
		"hashes": map[string]any{
			"sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeFast)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if client.calls == 0 {
		t.Fatalf("expected fast continue to query cloud")
	}
	if local.calls == 0 {
		t.Fatalf("expected fast continue to run local fallback")
	}
	if got := results[0].RiskAssessment.Stage; got != stageFastFallbackYara {
		t.Fatalf("expected stage %s, got %s", stageFastFallbackYara, got)
	}
}

func TestAnalyzerCloudLabelOverrideEscalatesToCritical(t *testing.T) {
	analyzer := Analyzer{
		Cloud: stubCloudClient{
			analysis: CloudAnalysis{
				CloudQueried:           true,
				LabelOverrideTriggered: true,
			},
			score: 10,
		},
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/webshell.php",
		"hashes": map[string]any{
			"sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].RiskAssessment.RiskLevel; got != RiskLevelCritical {
		t.Fatalf("expected %s, got %s", RiskLevelCritical, got)
	}
	if got := results[0].RiskAssessment.RiskScore; got < 95 {
		t.Fatalf("expected risk score >=95, got %.2f", got)
	}
}

func TestAnalyzerCloudFailSafePendingWhenProvidersPending(t *testing.T) {
	analyzer := Analyzer{
		Cloud: stubCloudClient{
			analysis: CloudAnalysis{
				CloudQueried:         false,
				FailSafeTriggered:    true,
				ProviderPendingCount: 2,
			},
			score: 0,
		},
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/unknown.bin",
		"hashes": map[string]any{
			"sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].RiskAssessment.RiskLevel; got != RiskLevelPending {
		t.Fatalf("expected %s, got %s", RiskLevelPending, got)
	}
	if got := results[0].RiskAssessment.RiskScore; got <= 20 {
		t.Fatalf("expected fail-safe score uplift, got %.2f", got)
	}
}

func TestAnalyzerCloudFailSafeSuspiciousOfflineWithoutPending(t *testing.T) {
	analyzer := Analyzer{
		Cloud: stubCloudClient{
			analysis: CloudAnalysis{
				CloudQueried:      false,
				FailSafeTriggered: true,
			},
			score: 0,
		},
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/unknown2.bin",
		"hashes": map[string]any{
			"sha256": "9999999999999999999999999999999999999999999999999999999999999999",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].RiskAssessment.RiskLevel; got != RiskLevelSuspiciousOffline {
		t.Fatalf("expected %s, got %s", RiskLevelSuspiciousOffline, got)
	}
}

func TestAnalyzerCloudDetectionOverrideForcesRiskLevel(t *testing.T) {
	analyzer := Analyzer{
		Cloud: stubCloudClient{
			analysis: CloudAnalysis{
				CloudQueried:               true,
				DetectionOverrideTriggered: true,
			},
			score: 6,
		},
	}
	records := []ScanRecord{{Raw: map[string]any{
		"target_type": "file",
		"target_path": "C:/tmp/suspicious.bin",
		"hashes": map[string]any{
			"sha256": "abababababababababababababababababababababababababababababababab",
		},
	}}}

	results, err := analyzer.Analyze(context.Background(), records, ModeCloudOnly)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if got := results[0].RiskAssessment.RiskLevel; got == RiskLevelNone {
		t.Fatalf("expected detection override to avoid no-risk level")
	}
	if got := results[0].RiskAssessment.RiskScore; got < 60 {
		t.Fatalf("expected detection override score floor 60, got %.2f", got)
	}
}

func TestUploadConcurrencyAutoScale(t *testing.T) {
	t.Parallel()

	analyzer := Analyzer{}
	small := analyzer.uploadConcurrency(ModeSmart, 16)
	large := analyzer.uploadConcurrency(ModeSmart, 2000)

	if small < 2 || small > 8 {
		t.Fatalf("unexpected small concurrency: %d", small)
	}
	if large < 2 || large > 8 {
		t.Fatalf("unexpected large concurrency: %d", large)
	}
	if large < small {
		t.Fatalf("expected large record-set concurrency >= small set, got small=%d large=%d", small, large)
	}
}

func TestUploadConcurrencyTunerKeepsBounds(t *testing.T) {
	t.Parallel()

	tuner := newUploadConcurrencyTuner(true)
	current := 4
	for i := 0; i < 20; i++ {
		next, _ := tuner.Next(current, 500)
		if next < 2 || next > 8 {
			t.Fatalf("tuner out of range: %d", next)
		}
		current = next
	}
}
