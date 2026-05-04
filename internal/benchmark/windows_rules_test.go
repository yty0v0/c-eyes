package benchmark

import "testing"

func TestLoadBenchmarkRuleSet(t *testing.T) {
	t.Parallel()

	for _, template := range []Template{TemplateWindows, TemplateLinux, TemplateEulerOS, TemplateKylin} {
		for _, level := range []BaselineLevel{BaselineLevel1, BaselineLevel2, BaselineLevel3, BaselineLevel4} {
			rules, err := loadBenchmarkRuleSet(template, level)
			if err != nil {
				t.Fatalf("loadBenchmarkRuleSet(%s,%s) returned error: %v", template, level, err)
			}
			if rules.Template != string(template) {
				t.Fatalf("expected template %q, got %q", template, rules.Template)
			}
			if len(rules.Checks) == 0 {
				t.Fatalf("expected rules for template %q level %q", template, level)
			}
		}
	}
}

func TestRuleAlignmentFollowsScriptBoundaries(t *testing.T) {
	t.Parallel()

	linuxLevel1, _ := loadBenchmarkRuleSet(TemplateLinux, BaselineLevel1)
	if ruleKind(linuxLevel1, "LNX-FS-001") != "int_lte" {
		t.Fatalf("expected linux level1 to evaluate by baseline requirement")
	}
	linuxLevel2, _ := loadBenchmarkRuleSet(TemplateLinux, BaselineLevel2)
	if ruleKind(linuxLevel2, "LNX-FS-001") != "int_lte" {
		t.Fatalf("expected linux level2 to evaluate by baseline requirement")
	}
	linuxLevel3, err := loadBenchmarkRuleSet(TemplateLinux, BaselineLevel3)
	if err != nil {
		t.Fatalf("load linux level3 rules: %v", err)
	}
	if ruleKind(linuxLevel3, "LNX-FS-001") != "int_lte" {
		t.Fatalf("expected linux level3 base checks to evaluate by baseline requirement, got %q", ruleKind(linuxLevel3, "LNX-FS-001"))
	}
	if !ruleExists(linuxLevel3, "LNX-NET-ADV-001") {
		t.Fatalf("expected linux level3 to include advanced scripted checks")
	}
	if ruleKind(linuxLevel3, "LNX-NET-ADV-001") != "int_equals" {
		t.Fatalf("expected linux level3 advanced network checks to be evaluated")
	}
	if ruleValue(linuxLevel3, "LNX-SVC-ADV-001") != "0" {
		t.Fatalf("expected linux level3 LNX-SVC-ADV-001 to evaluate to 0")
	}
	if ruleValue(linuxLevel3, "LNX-SVC-ADV-002") != "0" {
		t.Fatalf("expected linux level3 LNX-SVC-ADV-002 to evaluate to 0")
	}
	linuxLevel4, _ := loadBenchmarkRuleSet(TemplateLinux, BaselineLevel4)
	if ruleKind(linuxLevel4, "LNX-FS-001") != "int_lte" {
		t.Fatalf("expected linux level4 base checks to evaluate by baseline requirement, got %q", ruleKind(linuxLevel4, "LNX-FS-001"))
	}

	eulLevel1, _ := loadBenchmarkRuleSet(TemplateEulerOS, BaselineLevel1)
	if ruleKind(eulLevel1, "EUL-FS-001") != "int_lte" {
		t.Fatalf("expected euleros level1 to evaluate by baseline requirement")
	}
	eulLevel2, _ := loadBenchmarkRuleSet(TemplateEulerOS, BaselineLevel2)
	if ruleKind(eulLevel2, "EUL-FS-001") != "int_lte" {
		t.Fatalf("expected euleros level2 to evaluate by baseline requirement")
	}
	eulLevel3, err := loadBenchmarkRuleSet(TemplateEulerOS, BaselineLevel3)
	if err != nil {
		t.Fatalf("load euleros level3 rules: %v", err)
	}
	if ruleKind(eulLevel3, "EUL-FS-001") != "int_lte" {
		t.Fatalf("expected euleros level3 base checks to evaluate by baseline requirement")
	}
	if !ruleExists(eulLevel3, "EUL-NET-ADV-001") {
		t.Fatalf("expected euleros level3 to include advanced scripted checks")
	}
	if ruleKind(eulLevel3, "EUL-NET-ADV-001") != "int_equals" {
		t.Fatalf("expected euleros level3 network hardening checks to be evaluated")
	}
	if ruleKind(eulLevel3, "EUL-TIME-001") != "int_gt" {
		t.Fatalf("expected euleros level3 EUL-TIME-001 to use int_gt")
	}
	if ruleKind(eulLevel3, "EUL-TIME-002") != "bool_true" {
		t.Fatalf("expected euleros level3 EUL-TIME-002 to use bool_true")
	}
	if ruleKind(eulLevel3, "EUL-LOG-ADV-001") != "int_gt" {
		t.Fatalf("expected euleros level3 EUL-LOG-ADV-001 to use int_gt")
	}
	if ruleKind(eulLevel3, "EUL-HIST-001") != "int_gt" {
		t.Fatalf("expected euleros level3 EUL-HIST-001 to use int_gt")
	}
	eulLevel4, _ := loadBenchmarkRuleSet(TemplateEulerOS, BaselineLevel4)
	if ruleKind(eulLevel4, "EUL-FS-001") != "int_lte" {
		t.Fatalf("expected euleros level4 base checks to evaluate by baseline requirement")
	}

	kylLevel1, _ := loadBenchmarkRuleSet(TemplateKylin, BaselineLevel1)
	if ruleKind(kylLevel1, "KYL-FS-001") != "int_lte" {
		t.Fatalf("expected kylin level1 to evaluate by baseline requirement")
	}
	kylLevel2, _ := loadBenchmarkRuleSet(TemplateKylin, BaselineLevel2)
	if ruleKind(kylLevel2, "KYL-FS-001") != "int_lte" {
		t.Fatalf("expected kylin level2 to evaluate by baseline requirement")
	}
	kylLevel3, err := loadBenchmarkRuleSet(TemplateKylin, BaselineLevel3)
	if err != nil {
		t.Fatalf("load kylin level3 rules: %v", err)
	}
	if ruleKind(kylLevel3, "KYL-FS-001") != "int_lte" {
		t.Fatalf("expected kylin level3 base checks to evaluate by baseline requirement")
	}
	if !ruleExists(kylLevel3, "KYL-TRUST-001") {
		t.Fatalf("expected kylin level3 to include advanced scripted checks")
	}
	if ruleKind(kylLevel3, "KYL-TRUST-001") != "int_equals" {
		t.Fatalf("expected kylin level3 trust-file check to be evaluated")
	}
	if ruleValue(kylLevel3, "KYL-NET-ADV-001") != "0" {
		t.Fatalf("expected kylin level3 KYL-NET-ADV-001 to evaluate to 0")
	}
	if ruleKind(kylLevel3, "KYL-TIME-002") != "bool_true" {
		t.Fatalf("expected kylin level3 KYL-TIME-002 to use bool_true")
	}
	if ruleKind(kylLevel3, "KYL-LOG-ADV-001") != "int_gt" {
		t.Fatalf("expected kylin level3 KYL-LOG-ADV-001 to use int_gt")
	}
	if ruleKind(kylLevel3, "KYL-FS-ADV-001") != "int_gt" {
		t.Fatalf("expected kylin level3 KYL-FS-ADV-001 to use int_gt")
	}
	if ruleKind(kylLevel3, "KYL-HIST-001") != "int_gt" {
		t.Fatalf("expected kylin level3 KYL-HIST-001 to use int_gt")
	}
	kylLevel4, _ := loadBenchmarkRuleSet(TemplateKylin, BaselineLevel4)
	if ruleKind(kylLevel4, "KYL-FS-001") != "int_lte" {
		t.Fatalf("expected kylin level4 base checks to evaluate by baseline requirement")
	}

	winLevel1, _ := loadBenchmarkRuleSet(TemplateWindows, BaselineLevel1)
	expectedLevel1Kinds := map[string]string{
		"W-FW-001":   "bool_true",
		"W-PASS-001": "int_gte",
		"W-UAC-001":  "int_equals",
		"W-SMB-001":  "int_equals",
	}
	for id, kind := range expectedLevel1Kinds {
		if ruleKind(winLevel1, id) != kind {
			t.Fatalf("expected windows level1 %s to use %s evaluator", id, kind)
		}
	}
	winLevel2, _ := loadBenchmarkRuleSet(TemplateWindows, BaselineLevel2)
	for id, kind := range expectedLevel1Kinds {
		if ruleKind(winLevel2, id) != kind {
			t.Fatalf("expected windows level2 %s to use %s evaluator", id, kind)
		}
	}
	winLevel3, _ := loadBenchmarkRuleSet(TemplateWindows, BaselineLevel3)
	if !ruleExists(winLevel3, "W-TCP-001") {
		t.Fatalf("expected windows level3 to include advanced scripted checks")
	}
	expectedWinLevel3Kinds := map[string]string{
		"W-TCP-006":  "int_gte",
		"W-WU-001":   "int_gte",
		"W-SVC-004":  "bool_true",
		"W-EVENT-001":"int_gte",
		"W-PRIV-003":"string_not_contains",
		"W-RDP-001": "int_gte",
	}
	for id, kind := range expectedWinLevel3Kinds {
		if ruleKind(winLevel3, id) != kind {
			t.Fatalf("expected windows level3 %s to use %s evaluator", id, kind)
		}
	}
	winLevel4, _ := loadBenchmarkRuleSet(TemplateWindows, BaselineLevel4)
	if !ruleExists(winLevel4, "W-AUTORUN-001") {
		t.Fatalf("expected windows level4 to include W-AUTORUN-001 because the script has a pre_cmd for it")
	}
	if ruleKind(winLevel4, "W-PASS-001") != "int_gte" {
		t.Fatalf("expected windows level4 base checks to evaluate by baseline requirement")
	}
	if ruleKind(winLevel4, "W-AUTORUN-001") != "int_equals" {
		t.Fatalf("expected windows level4 W-AUTORUN-001 to be evaluated")
	}
}

func ruleExists(rules benchmarkRuleSet, id string) bool {
	for _, rule := range rules.Checks {
		if rule.ID == id {
			return true
		}
	}
	return false
}

func ruleValue(rules benchmarkRuleSet, id string) string {
	for _, rule := range rules.Checks {
		if rule.ID == id {
			return rule.Evaluator.Value
		}
	}
	return ""
}

func ruleKind(rules benchmarkRuleSet, id string) string {
	for _, rule := range rules.Checks {
		if rule.ID == id {
			return rule.Evaluator.Kind
		}
	}
	return ""
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
}

func TestInformationalRuleSeverityNormalizesToInfo(t *testing.T) {
	t.Parallel()

	result := &benchmarkCheckResult{}
	rule := benchmarkRule{
		ID:          "LNX-ACC-001",
		Name:        "test",
		Severity:    "high",
		Description: "desc",
		Evaluator: benchmarkRuleEvaluator{
			Kind: "informational",
		},
	}
	applyBenchmarkRule(rule, result)
	if result.Status.StatusReason != "informational_check" {
		t.Fatalf("expected informational_check, got %#v", result.Status)
	}
	if result.Severity != "" {
		t.Fatalf("expected informational severity to be empty, got %q", result.Severity)
	}
}
