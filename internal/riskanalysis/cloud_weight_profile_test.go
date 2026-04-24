package riskanalysis

import (
	"context"
	"errors"
	"testing"
)

type fixedCloudClient struct {
	analysis CloudAnalysis
	score    float64
	err      error
}

func (f fixedCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return f.analysis, f.score, f.err
}

func TestMultiCloudQueryUsesMaxScore(t *testing.T) {
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "virustotal",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{CloudQueried: true, CloudProvider: "virustotal"},
					score:    80,
				},
			},
			{
				Name: "otx",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{CloudQueried: true, CloudProvider: "otx"},
					score:    20,
				},
			},
		},
	}

	analysis, score, err := client.Query(context.Background(), Hashes{Sha256: "abc"})
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if !analysis.CloudQueried {
		t.Fatalf("expected cloud queried")
	}
	if score != 80 {
		t.Fatalf("unexpected score, want 80 got %.2f", score)
	}
}

func TestMultiCloudQueryUsesEffectiveProvidersOnly(t *testing.T) {
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "virustotal",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{CloudQueried: true, CloudProvider: "virustotal", Malicious: 53, TotalEngines: 100, DetectionRate: "53/100"},
					score:    53,
				},
			},
			{
				Name: "malwarebazaar",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{CloudQueried: true, CloudProvider: "malwarebazaar"},
					score:    0,
				},
			},
			{
				Name: "triage",
				Client: fixedCloudClient{
					err: errors.New("cloud api key is required"),
				},
			},
		},
	}

	analysis, score, err := client.Query(context.Background(), Hashes{Sha256: "abc"})
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if score != 53 {
		t.Fatalf("expected effective max score 53, got %.2f", score)
	}
	if analysis.EffectiveProviderCount != 1 {
		t.Fatalf("expected effective provider count 1, got %d", analysis.EffectiveProviderCount)
	}
	if analysis.ProviderNoResultCount == 0 {
		t.Fatalf("expected no-result provider counted")
	}
	if analysis.ProviderFailedCount == 0 {
		t.Fatalf("expected failed provider counted")
	}
	if analysis.EffectiveAverageScore != 53 {
		t.Fatalf("expected effective average 53, got %.2f", analysis.EffectiveAverageScore)
	}
}

func TestMultiCloudQueryThreatLabelOverride(t *testing.T) {
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "virustotal",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{
						CloudQueried:  true,
						CloudProvider: "virustotal",
						ThreatLabels:  []string{"trojan.webshell"},
					},
					score: 12,
				},
			},
		},
	}

	analysis, score, err := client.Query(context.Background(), Hashes{Sha256: "abc"})
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if !analysis.LabelOverrideTriggered {
		t.Fatalf("expected label override triggered")
	}
	if score < 95 {
		t.Fatalf("expected override score floor 95, got %.2f", score)
	}
}

func TestMultiCloudQueryDetectionThresholdOverride(t *testing.T) {
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "virustotal",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{
						CloudQueried:  true,
						CloudProvider: "virustotal",
						Malicious:     6,
						TotalEngines:  100,
						DetectionRate: "6/100",
					},
					score: 6,
				},
			},
		},
	}

	analysis, score, err := client.Query(context.Background(), Hashes{Sha256: "abc"})
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if !analysis.DetectionOverrideTriggered {
		t.Fatalf("expected detection override triggered")
	}
	if score != 6 {
		t.Fatalf("expected base max score to remain 6, got %.2f", score)
	}
}

func TestMultiCloudQueryFailSafeWhenProvidersDegraded(t *testing.T) {
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "virustotal",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{
						CloudQueried:  true,
						CloudProvider: "virustotal",
						Malicious:     0,
						TotalEngines:  70,
						DetectionRate: "0/70",
					},
					score: 0,
				},
			},
			{
				Name: "malwarebazaar",
				Client: fixedCloudClient{
					err: context.DeadlineExceeded,
				},
			},
			{
				Name: "triage",
				Client: fixedCloudClient{
					err: errors.New("cloud api key is required"),
				},
			},
			{
				Name: "otx",
				Client: fixedCloudClient{
					err: ErrRateLimited,
				},
			},
			{
				Name: "hybrid_analysis",
				Client: fixedCloudClient{
					analysis: CloudAnalysis{CloudQueried: true, CloudProvider: "hybrid_analysis"},
					score:    0,
				},
			},
		},
	}

	analysis, score, err := client.Query(context.Background(), Hashes{Sha256: "abc"})
	if err != nil {
		t.Fatalf("Query error: %v", err)
	}
	if !analysis.FailSafeTriggered {
		t.Fatalf("expected fail-safe triggered")
	}
	if analysis.ProviderTotalCount != 5 {
		t.Fatalf("expected provider total 5, got %d", analysis.ProviderTotalCount)
	}
	if analysis.ProviderTimeoutCount == 0 || analysis.ProviderFailedCount == 0 || analysis.ProviderPendingCount == 0 {
		t.Fatalf("expected timeout/failed/pending counts to be tracked")
	}
	if score != 0 {
		t.Fatalf("expected score 0 when no malicious effective verdict, got %.2f", score)
	}
}

func TestTriageScoreToRisk(t *testing.T) {
	if got := triageScoreToRisk(8); got < 90 {
		t.Fatalf("expected >=90 for triage score 8, got %.2f", got)
	}
	if got := triageScoreToRisk(10); got != 100 {
		t.Fatalf("expected 100 for triage score 10, got %.2f", got)
	}
	if got := triageScoreToRisk(0.8); got < 90 {
		t.Fatalf("expected normalized 0.8 to map to high risk, got %.2f", got)
	}
}

func TestOTXPulseScore(t *testing.T) {
	if got := otxPulseScore(1, nil); got != 20 {
		t.Fatalf("expected score 20 for single pulse without trust bonus, got %.2f", got)
	}
	if got := otxPulseScore(5, nil); got != 50 {
		t.Fatalf("expected score 50 for five pulses without trust bonus, got %.2f", got)
	}
	if got := otxPulseScore(1, []otxPulse{{AuthorName: "Alien Labs"}}); got != 35 {
		t.Fatalf("expected trust bonus for Alien Labs, got %.2f", got)
	}
}

func TestVTMajorEngineBonus(t *testing.T) {
	results := map[string]vtEngineResult{
		"Microsoft": {Category: "malicious"},
		"Kaspersky": {Category: "suspicious"},
		"UnknownAV": {Category: "malicious"},
	}
	if got := vtMajorEngineBonus(results); got != 8 {
		t.Fatalf("expected major engine bonus 8, got %.2f", got)
	}
}
