package riskanalysis

import "testing"

func TestRiskLevelFromScore(t *testing.T) {
	cases := []struct {
		score float64
		level string
	}{
		{0, RiskLevelNone},
		{20, RiskLevelNone},
		{21, RiskLevelLow},
		{50, RiskLevelLow},
		{51, RiskLevelMedium},
		{80, RiskLevelMedium},
		{81, RiskLevelHigh},
		{100, RiskLevelHigh},
	}
	for _, c := range cases {
		if got := RiskLevelFromScore(c.score); got != c.level {
			t.Fatalf("score %v expected %s got %s", c.score, c.level, got)
		}
	}
}

func TestWeightedScore(t *testing.T) {
	score := WeightedScore(90, 40, 0.6, 0.4, true, true)
	if score <= 0 {
		t.Fatalf("expected weighted score to be >0")
	}

	score = WeightedScore(90, 40, 0, 0, true, true)
	if score != 0 {
		t.Fatalf("expected zero score when weights are zero")
	}
}
