package riskanalysis

import (
	"context"
	"fmt"
	"testing"
)

type benchmarkLocalMatcher struct {
	analysis LocalAnalysis
	score    float64
}

func (m benchmarkLocalMatcher) Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error) {
	return m.analysis, m.score, nil
}

func (m benchmarkLocalMatcher) ConcurrentSafe() bool {
	return true
}

type benchmarkCloudClient struct {
	analysis CloudAnalysis
	score    float64
}

func (c benchmarkCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return c.analysis, c.score, nil
}

func (c benchmarkCloudClient) QueryFast(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return c.analysis, c.score, nil
}

func (c benchmarkCloudClient) QuerySmart(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	return c.analysis, c.score, nil
}

func (c benchmarkCloudClient) QueryDeep(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	return c.analysis, c.score, nil
}

type benchmarkWhitelistEngine struct {
	analysis WhitelistAnalysis
}

func (w benchmarkWhitelistEngine) Evaluate(ctx context.Context, meta TargetMetadata, record ScanRecord, stage string) (WhitelistAnalysis, error) {
	return w.analysis, nil
}

func BenchmarkAnalyzerSmart(b *testing.B) {
	benchmarkAnalyzerMode(b, ModeSmart)
}

func BenchmarkAnalyzerDeep(b *testing.B) {
	benchmarkAnalyzerMode(b, ModeDeep)
}

func benchmarkAnalyzerMode(b *testing.B, mode AnalysisMode) {
	records := benchmarkRecords(128)
	local := benchmarkLocalMatcher{
		analysis: LocalAnalysis{
			LocalMatched: true,
			YaraResults: []YaraRuleMatch{
				{
					RuleName: "packed_loader",
					Tags:     []string{"packed", "anti_debug", "rat"},
					Severity: 70,
				},
			},
		},
		score: 70,
	}
	cloud := benchmarkCloudClient{
		analysis: CloudAnalysis{
			CloudQueried:   true,
			CloudProvider:  "virustotal",
			CloudProviders: []string{"virustotal", "otx"},
			Malicious:      5,
			TotalEngines:   70,
			DetectionRate:  "5/70",
			ThreatLabels:   []string{"rat", "packed"},
		},
		score: 62,
	}
	whitelist := benchmarkWhitelistEngine{
		analysis: WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionContinue,
			Source:   "whitelist_funnel",
		},
	}

	analyzer := Analyzer{
		Local:       local,
		Cloud:       cloud,
		Whitelist:   whitelist,
		LocalWeight: 0.6,
		CloudWeight: 0.4,
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := analyzer.Analyze(ctx, records, mode); err != nil {
			b.Fatalf("Analyze error: %v", err)
		}
	}
}

func benchmarkRecords(n int) []ScanRecord {
	records := make([]ScanRecord, 0, n)
	for i := 0; i < n; i++ {
		path := fmt.Sprintf("C:/bench/sample-%03d.bin", i)
		hash := fmt.Sprintf("%064x", i+1)
		records = append(records, ScanRecord{
			Raw: map[string]any{
				"target_type": "file",
				"target_path": path,
				"hashes": map[string]any{
					"sha256": hash,
				},
				"process_command": "sample.exe --arg",
			},
		})
	}
	return records
}
