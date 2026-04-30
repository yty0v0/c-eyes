package benchmark

import "strings"

type statusRuleType int

const (
	statusRuleUnknown statusRuleType = iota
	statusRuleInformational
)

type statusRule struct {
	Type statusRuleType
}

var informationalExecutionFailureHints = []string{
	"failed to execute",
	"execution failed",
	"script execution failed",
	"command not found",
	"no such file or directory",
	"permission denied",
	"is not recognized as an internal or external command",
	"syntax error near unexpected token",
	"traceback (most recent call last)",
}

var templateStatusRules = map[Template]map[string]statusRule{
	TemplateWindows: {
		"0":  {Type: statusRuleInformational},
		"1":  {Type: statusRuleInformational},
		"2":  {Type: statusRuleInformational},
		"3":  {Type: statusRuleInformational},
		"4":  {Type: statusRuleInformational},
		"5":  {Type: statusRuleInformational},
		"6":  {Type: statusRuleInformational},
		"7":  {Type: statusRuleInformational},
		"8":  {Type: statusRuleInformational},
		"9":  {Type: statusRuleInformational},
		"10": {Type: statusRuleInformational},
		"12": {Type: statusRuleInformational},
	},
	TemplateLinux: {
		"0":  {Type: statusRuleInformational},
		"1":  {Type: statusRuleInformational},
		"2":  {Type: statusRuleInformational},
		"3":  {Type: statusRuleInformational},
		"4":  {Type: statusRuleInformational},
		"5":  {Type: statusRuleInformational},
		"6":  {Type: statusRuleInformational},
		"7":  {Type: statusRuleInformational},
		"8":  {Type: statusRuleInformational},
		"9":  {Type: statusRuleInformational},
		"10": {Type: statusRuleInformational},
		"11": {Type: statusRuleInformational},
		"12": {Type: statusRuleInformational},
		"13": {Type: statusRuleInformational},
		"14": {Type: statusRuleInformational},
		"15": {Type: statusRuleInformational},
		"16": {Type: statusRuleInformational},
		"17": {Type: statusRuleInformational},
		"19": {Type: statusRuleInformational},
		"20": {Type: statusRuleInformational},
		"21": {Type: statusRuleInformational},
		"22": {Type: statusRuleInformational},
	},
	TemplateEulerOS: {
		"0":  {Type: statusRuleInformational},
		"1":  {Type: statusRuleInformational},
		"2":  {Type: statusRuleInformational},
		"3":  {Type: statusRuleInformational},
		"4":  {Type: statusRuleInformational},
		"5":  {Type: statusRuleInformational},
		"6":  {Type: statusRuleInformational},
		"7":  {Type: statusRuleInformational},
		"8":  {Type: statusRuleInformational},
		"9":  {Type: statusRuleInformational},
		"10": {Type: statusRuleInformational},
		"11": {Type: statusRuleInformational},
		"14": {Type: statusRuleInformational},
		"18": {Type: statusRuleInformational},
		"21": {Type: statusRuleInformational},
	},
	TemplateKylin: {
		"1":  {Type: statusRuleInformational},
		"2":  {Type: statusRuleInformational},
		"3":  {Type: statusRuleInformational},
		"4":  {Type: statusRuleInformational},
		"5":  {Type: statusRuleInformational},
		"6":  {Type: statusRuleInformational},
		"7":  {Type: statusRuleInformational},
		"8":  {Type: statusRuleInformational},
		"9":  {Type: statusRuleInformational},
		"10": {Type: statusRuleInformational},
		"11": {Type: statusRuleInformational},
		"12": {Type: statusRuleInformational},
		"13": {Type: statusRuleInformational},
		"14": {Type: statusRuleInformational},
		"15": {Type: statusRuleInformational},
	},
}

func deriveStatusAssessmentByTemplateRule(template Template, checkID, value string) (statusAssessment, bool) {
	rules, ok := templateStatusRules[template]
	if !ok {
		return statusAssessment{}, false
	}
	rule, ok := rules[strings.TrimSpace(checkID)]
	if !ok {
		return statusAssessment{}, false
	}

	v := normalizeLowerTrim(value)
	if v == "" {
		return statusAssessment{
			Status:          "unknown",
			Evaluated:       false,
			StatusReason:    "informational_check",
			ExecutionStatus: "ok",
		}, true
	}

	switch rule.Type {
	case statusRuleInformational:
		// For informational rows, only explicit script/runtime failures are treated as fail.
		// Domain values such as "Disabled/Stopped" are inventory fields and stay unknown.
		if containsAnyPhrase(v, informationalExecutionFailureHints) {
			return statusAssessment{
				Status:          "fail",
				Evaluated:       true,
				StatusReason:    "execution_error",
				ExecutionStatus: "error",
			}, true
		}
		return statusAssessment{
			Status:          "unknown",
			Evaluated:       false,
			StatusReason:    "informational_check",
			ExecutionStatus: "ok",
		}, true
	default:
		return statusAssessment{}, false
	}
}

func containsAnyStatusToken(text string, tokens []string) bool {
	for _, token := range tokens {
		if containsStatusToken(text, token) {
			return true
		}
	}
	return false
}

func containsStatusToken(text, token string) bool {
	if token = normalizeLowerTrim(token); token == "" {
		return false
	}
	text = normalizeLowerTrim(text)
	if text == "" || len(token) > len(text) {
		return false
	}

	start := 0
	for {
		offset := strings.Index(text[start:], token)
		if offset < 0 {
			return false
		}
		idx := start + offset
		leftOK := idx == 0 || !isStatusTokenChar(text[idx-1])
		rightIdx := idx + len(token)
		rightOK := rightIdx >= len(text) || !isStatusTokenChar(text[rightIdx])
		if leftOK && rightOK {
			return true
		}
		start = idx + 1
		if start >= len(text) {
			return false
		}
	}
}

func containsAnyPhrase(text string, phrases []string) bool {
	normalizedText := normalizeLowerTrim(text)
	if normalizedText == "" {
		return false
	}
	for _, phrase := range phrases {
		normalizedPhrase := normalizeLowerTrim(phrase)
		if normalizedPhrase == "" {
			continue
		}
		if strings.Contains(normalizedText, normalizedPhrase) {
			return true
		}
	}
	return false
}

func isStatusTokenChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_'
}
