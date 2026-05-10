package riskanalysis

import "testing"

func TestBuildSummaryExcludesNoneAndCountsSpecialLevels(t *testing.T) {
	results := []AnalysisResult{
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelNone}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelLow}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelMedium}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelHigh}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelCritical}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelPending}},
		{RiskAssessment: RiskAssessment{RiskLevel: RiskLevelSuspiciousOffline}},
	}

	summary := BuildSummary(results)
	if summary.Total != 6 {
		t.Fatalf("expected total 6, got %d", summary.Total)
	}
	if summary.Low != 1 || summary.Medium != 1 || summary.High != 1 || summary.Critical != 1 || summary.Pending != 1 || summary.SuspiciousOffline != 1 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}
}
