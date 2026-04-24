package riskanalysis

import "testing"

func TestFallbackSeverityKnownFamilies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		ruleName string
		tags     []string
		min      int
	}{
		{
			name:     "webshell",
			ruleName: "webshell_php_generic_eval",
			min:      90,
		},
		{
			name:     "ransomware",
			ruleName: "Ransom_Babuk",
			min:      95,
		},
		{
			name:     "coinminer",
			ruleName: "Rule_Coinminer_ELF_Format",
			min:      80,
		},
		{
			name:     "malicious tag",
			ruleName: "UnknownRule",
			tags:     []string{"MALW"},
			min:      85,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := fallbackSeverity(c.ruleName, c.tags)
			if got < c.min {
				t.Fatalf("expected severity >= %d, got %d", c.min, got)
			}
		})
	}
}

func TestFallbackSeverityDefaultForUnclassifiedMatch(t *testing.T) {
	t.Parallel()

	if got := fallbackSeverity("fscan_rule_1", nil); got != defaultMatchedSeverity {
		t.Fatalf("expected default matched severity %d, got %d", defaultMatchedSeverity, got)
	}
}

func TestFallbackSeverityZeroForEmptySignal(t *testing.T) {
	t.Parallel()

	if got := fallbackSeverity("", nil); got != 0 {
		t.Fatalf("expected empty signal severity 0, got %d", got)
	}
}
