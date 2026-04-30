package benchmark

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"edrsystem/internal/benchmark/assets"

	"gopkg.in/yaml.v3"
)

type benchmarkRuleSet struct {
	Version  int             `yaml:"version"`
	Template string          `yaml:"template"`
	Checks   []benchmarkRule `yaml:"checks"`
}

type benchmarkRule struct {
	SourceID       string                 `yaml:"source_id"`
	ID             string                 `yaml:"id"`
	Name           string                 `yaml:"name"`
	Category       string                 `yaml:"category"`
	Description    string                 `yaml:"description"`
	Expected       string                 `yaml:"expected"`
	Severity       string                 `yaml:"severity"`
	Recommendation string                 `yaml:"recommendation"`
	Evaluator      benchmarkRuleEvaluator `yaml:"evaluator"`
}

type benchmarkRuleEvaluator struct {
	Kind  string `yaml:"kind"`
	Field string `yaml:"field"`
	Value string `yaml:"value"`
	Min   *int64 `yaml:"min"`
	Max   *int64 `yaml:"max"`
}

type benchmarkCheckResult struct {
	ID             string
	SectionType    string
	Command        string
	Actual         string
	Evidence       string
	Eval           map[string]any
	Status         statusAssessment
	Name           string
	Category       string
	Description    string
	Expected       string
	Severity       string
	Recommendation string
}

func loadBenchmarkRuleSet(template Template) (benchmarkRuleSet, error) {
	assetPath := benchmarkRuleAssetPath(template)
	payload, err := assets.Files.ReadFile(assetPath)
	if err != nil {
		return benchmarkRuleSet{}, fmt.Errorf("read benchmark rules %s failed: %w", assetPath, err)
	}

	var rules benchmarkRuleSet
	if err := yaml.Unmarshal(payload, &rules); err != nil {
		return benchmarkRuleSet{}, fmt.Errorf("decode benchmark rules failed: %w", err)
	}
	if rules.Template != string(template) {
		return benchmarkRuleSet{}, fmt.Errorf("invalid benchmark rules: template=%q", rules.Template)
	}
	if len(rules.Checks) == 0 {
		return benchmarkRuleSet{}, fmt.Errorf("invalid benchmark rules: no checks defined")
	}
	return rules, nil
}

func buildBenchmarkRuleIndex(rules benchmarkRuleSet) map[string]benchmarkRule {
	index := make(map[string]benchmarkRule, len(rules.Checks))
	for _, rule := range rules.Checks {
		id := strings.TrimSpace(rule.SourceID)
		if id == "" {
			id = strings.TrimSpace(rule.ID)
		}
		if id == "" {
			continue
		}
		index[id] = rule
	}
	return index
}

func applyBenchmarkRule(rule benchmarkRule, result *benchmarkCheckResult) {
	if result == nil {
		return
	}
	result.ID = firstNonEmpty(strings.TrimSpace(rule.ID), result.ID)
	result.Name = strings.TrimSpace(rule.Name)
	result.Category = firstNonEmpty(strings.TrimSpace(rule.Category), result.Category)
	result.Description = strings.TrimSpace(rule.Description)
	result.Expected = strings.TrimSpace(rule.Expected)
	result.Severity = strings.TrimSpace(rule.Severity)
	result.Recommendation = strings.TrimSpace(rule.Recommendation)
	result.Status = evaluateBenchmarkRule(rule, result.Eval)
}

func evaluateBenchmarkRule(rule benchmarkRule, eval map[string]any) statusAssessment {
	kind := normalizeLowerTrim(rule.Evaluator.Kind)
	switch kind {
	case "", "informational":
		return statusAssessment{
			Status:          "unknown",
			Evaluated:       false,
			StatusReason:    "informational_check",
			ExecutionStatus: "ok",
		}
	case "bool_true":
		value, ok := lookupEvalBool(eval, rule.Evaluator.Field)
		if !ok {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if value {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "string_equals":
		actual, ok := lookupEvalString(eval, rule.Evaluator.Field)
		if !ok {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(rule.Evaluator.Value)) {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "string_not_equals":
		actual, ok := lookupEvalString(eval, rule.Evaluator.Field)
		if !ok {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if !strings.EqualFold(strings.TrimSpace(actual), strings.TrimSpace(rule.Evaluator.Value)) {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "int_equals":
		actual, ok := lookupEvalInt(eval, rule.Evaluator.Field)
		if !ok {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		expected, err := strconv.ParseInt(strings.TrimSpace(rule.Evaluator.Value), 10, 64)
		if err != nil {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if actual == expected {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "int_gte":
		actual, ok := lookupEvalInt(eval, rule.Evaluator.Field)
		if !ok || rule.Evaluator.Min == nil {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if actual >= *rule.Evaluator.Min {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "int_lte":
		actual, ok := lookupEvalInt(eval, rule.Evaluator.Field)
		if !ok || rule.Evaluator.Max == nil {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if actual <= *rule.Evaluator.Max {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "int_between":
		actual, ok := lookupEvalInt(eval, rule.Evaluator.Field)
		if !ok || rule.Evaluator.Min == nil || rule.Evaluator.Max == nil {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		if actual >= *rule.Evaluator.Min && actual <= *rule.Evaluator.Max {
			return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	case "int_in":
		actual, ok := lookupEvalInt(eval, rule.Evaluator.Field)
		if !ok {
			return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
		}
		for _, item := range strings.Split(rule.Evaluator.Value, ",") {
			expected, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64)
			if err == nil && actual == expected {
				return statusAssessment{Status: "pass", Evaluated: true, StatusReason: "policy_match", ExecutionStatus: "ok"}
			}
		}
		return statusAssessment{Status: "fail", Evaluated: true, StatusReason: "policy_violation", ExecutionStatus: "ok"}
	default:
		return statusAssessment{Status: "unknown", Evaluated: false, StatusReason: "undetermined", ExecutionStatus: "ok"}
	}
}

func lookupEvalInt(values map[string]any, field string) (int64, bool) {
	if values == nil {
		return 0, false
	}
	current, ok := lookupEvalValue(values, field)
	if !ok {
		return 0, false
	}
	switch typed := current.(type) {
	case int:
		return int64(typed), true
	case int32:
		return int64(typed), true
	case int64:
		return typed, true
	case uint32:
		return int64(typed), true
	case uint64:
		return int64(typed), true
	case *int:
		if typed == nil {
			return 0, false
		}
		return int64(*typed), true
	case *int64:
		if typed == nil {
			return 0, false
		}
		return *typed, true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func lookupEvalBool(values map[string]any, field string) (bool, bool) {
	if values == nil {
		return false, false
	}
	current, ok := lookupEvalValue(values, field)
	if !ok {
		return false, false
	}
	switch typed := current.(type) {
	case bool:
		return typed, true
	case *bool:
		if typed == nil {
			return false, false
		}
		return *typed, true
	default:
		return false, false
	}
}

func lookupEvalString(values map[string]any, field string) (string, bool) {
	if values == nil {
		return "", false
	}
	current, ok := lookupEvalValue(values, field)
	if !ok {
		return "", false
	}
	switch typed := current.(type) {
	case string:
		return typed, true
	case *string:
		if typed == nil {
			return "", false
		}
		return *typed, true
	default:
		return "", false
	}
}

func lookupEvalValue(values map[string]any, field string) (any, bool) {
	if values == nil {
		return nil, false
	}
	trimmed := strings.TrimSpace(field)
	if trimmed == "" {
		return nil, false
	}
	current := any(values)
	for _, part := range strings.Split(trimmed, ".") {
		key := strings.TrimSpace(part)
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := obj[key]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func benchmarkRuleAssetPath(template Template) string {
	folder := string(template)
	return path.Join(folder, folder+"-rules.yaml")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
