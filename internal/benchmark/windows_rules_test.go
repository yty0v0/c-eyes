package benchmark

import "testing"

func TestLoadBenchmarkRuleSet(t *testing.T) {
	t.Parallel()

	for _, template := range []Template{TemplateWindows, TemplateLinux, TemplateEulerOS, TemplateKylin} {
		rules, err := loadBenchmarkRuleSet(template)
		if err != nil {
			t.Fatalf("loadBenchmarkRuleSet(%s) returned error: %v", template, err)
		}
		if rules.Template != string(template) {
			t.Fatalf("expected template %q, got %q", template, rules.Template)
		}
		if len(rules.Checks) == 0 {
			t.Fatalf("expected rules for template %q", template)
		}
	}
}

func TestEvaluateBenchmarkRuleBoolTrue(t *testing.T) {
	t.Parallel()

	rule := benchmarkRule{
		ID: "W-FW-001",
		Evaluator: benchmarkRuleEvaluator{
			Kind:  "bool_true",
			Field: "enabled",
		},
	}

	pass := evaluateBenchmarkRule(rule, map[string]any{"enabled": true})
	if pass.Status != "pass" || !pass.Evaluated {
		t.Fatalf("expected pass evaluated rule, got %#v", pass)
	}

	fail := evaluateBenchmarkRule(rule, map[string]any{"enabled": false})
	if fail.Status != "fail" || !fail.Evaluated {
		t.Fatalf("expected fail evaluated rule, got %#v", fail)
	}
}

func TestEvaluateBenchmarkRuleIntComparisons(t *testing.T) {
	t.Parallel()

	max90 := int64(90)
	lteRule := benchmarkRule{
		ID: "FS-001",
		Evaluator: benchmarkRuleEvaluator{
			Kind:  "int_lte",
			Field: "highest_used_percent",
			Max:   &max90,
		},
	}
	if got := evaluateBenchmarkRule(lteRule, map[string]any{"highest_used_percent": int64(85)}); got.Status != "pass" {
		t.Fatalf("expected pass for int_lte rule, got %#v", got)
	}
	if got := evaluateBenchmarkRule(lteRule, map[string]any{"highest_used_percent": int64(95)}); got.Status != "fail" {
		t.Fatalf("expected fail for int_lte rule, got %#v", got)
	}

	min2 := int64(2)
	gteRule := benchmarkRule{
		ID: "FILE-001",
		Evaluator: benchmarkRuleEvaluator{
			Kind:  "int_gte",
			Field: "protected_file_count",
			Min:   &min2,
		},
	}
	if got := evaluateBenchmarkRule(gteRule, map[string]any{"protected_file_count": int64(3)}); got.Status != "pass" {
		t.Fatalf("expected pass for int_gte rule, got %#v", got)
	}
	if got := evaluateBenchmarkRule(gteRule, map[string]any{"protected_file_count": int64(1)}); got.Status != "fail" {
		t.Fatalf("expected fail for int_gte rule, got %#v", got)
	}
}
