package riskanalysis

func BuildSummary(results []AnalysisResult) Summary {
	var summary Summary
	for _, result := range results {
		switch result.RiskAssessment.RiskLevel {
		case RiskLevelCritical:
			summary.Critical++
			summary.Total++
		case RiskLevelHigh:
			summary.High++
			summary.Total++
		case RiskLevelMedium:
			summary.Medium++
			summary.Total++
		case RiskLevelLow:
			summary.Low++
			summary.Total++
		case RiskLevelPending:
			summary.Pending++
			summary.Total++
		case RiskLevelSuspiciousOffline:
			summary.SuspiciousOffline++
			summary.Total++
		}
	}
	return summary
}
