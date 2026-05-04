package benchmark

import (
	"sort"
	"strings"
	"testing"
)

func TestUnixNativeProfilesAreFullyMappedByRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		template Template
	}{
		{template: TemplateLinux},
		{template: TemplateEulerOS},
		{template: TemplateKylin},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.template), func(t *testing.T) {
			t.Parallel()

			profile, err := nativeProfileForTemplate(tc.template)
			if err != nil {
				t.Fatalf("nativeProfileForTemplate(%s): %v", tc.template, err)
			}
			profileFlags := nativeProfileFlagSet(profile)
			if len(profileFlags) == 0 {
				t.Fatalf("expected native profile flags for template %s", tc.template)
			}

			rules, err := loadBenchmarkRuleSet(tc.template, BaselineLevel1)
			if err != nil {
				t.Fatalf("loadBenchmarkRuleSet(%s): %v", tc.template, err)
			}
			ruleFlags := ruleSourceFlagSet(rules)
			if diff := missingFlags(profileFlags, ruleFlags); len(diff) > 0 {
				t.Fatalf("rule set missing native profile flags for %s: %v", tc.template, diff)
			}
		})
	}
}

func nativeProfileFlagSet(profile nativeTemplateProfile) map[string]struct{} {
	flags := make(map[string]struct{}, len(profile.checks))
	for _, check := range profile.checks {
		flag := strings.TrimSpace(check.id)
		if flag == "" {
			continue
		}
		flags[flag] = struct{}{}
	}
	return flags
}

func ruleSourceFlagSet(rules benchmarkRuleSet) map[string]struct{} {
	flags := make(map[string]struct{}, len(rules.Checks))
	for _, rule := range rules.Checks {
		flag := strings.TrimSpace(rule.SourceID)
		if flag == "" {
			flag = strings.TrimSpace(rule.ID)
		}
		if flag == "" {
			continue
		}
		flags[flag] = struct{}{}
	}
	return flags
}

func missingFlags(expected, actual map[string]struct{}) []string {
	var missing []string
	for flag := range expected {
		if _, ok := actual[flag]; ok {
			continue
		}
		missing = append(missing, flag)
	}
	sort.Strings(missing)
	return missing
}
