package riskanalysis

import "math"

const (
	RiskLevelNone              = "无风险"
	RiskLevelLow               = "低风险"
	RiskLevelMedium            = "中风险"
	RiskLevelHigh              = "高风险"
	RiskLevelCritical          = "高危"
	RiskLevelPending           = "分析中"
	RiskLevelSuspiciousOffline = "可疑-需本地核实"
)

func RiskLevelFromScore(score float64) string {
	switch {
	case score <= 20:
		return RiskLevelNone
	case score <= 50:
		return RiskLevelLow
	case score <= 80:
		return RiskLevelMedium
	default:
		return RiskLevelHigh
	}
}

func ClampScore(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0
	}
	return score
}

func WeightedScore(localScore, cloudScore float64, localWeight, cloudWeight float64, localEnabled, cloudEnabled bool) float64 {
	if !localEnabled {
		localWeight = 0
	}
	if !cloudEnabled {
		cloudWeight = 0
	}
	if localWeight < 0 {
		localWeight = 0
	}
	if cloudWeight < 0 {
		cloudWeight = 0
	}
	totalWeight := localWeight + cloudWeight
	if totalWeight <= 0 {
		return 0
	}
	score := (localScore*localWeight + cloudScore*cloudWeight) / totalWeight
	return ClampScore(score)
}

func LocalScoreFromMatches(matches []YaraRuleMatch) float64 {
	maxSeverity := 0
	for _, match := range matches {
		if match.Severity > maxSeverity {
			maxSeverity = match.Severity
		}
	}
	return ClampScore(float64(maxSeverity))
}

func CloudScoreFromAnalysis(analysis CloudAnalysis) float64 {
	if analysis.TotalEngines <= 0 {
		return 0
	}
	score := float64(analysis.Malicious) / float64(analysis.TotalEngines) * 100
	return ClampScore(score)
}
