//go:build linux

package benchmark

import (
	"context"
	"os"
	"testing"
)

func TestLiveLinuxFamilyNativeCollectorsExposeRuleFields(t *testing.T) {
	if os.Getenv("UNIX_BENCHMARK_LIVE") != "1" {
		t.Skip("set UNIX_BENCHMARK_LIVE=1 to run live Linux-family benchmark validation")
	}
	if os.Geteuid() != 0 {
		t.Skip("live Linux-family benchmark validation requires root privilege")
	}

	cases := []struct {
		name     string
		template Template
		level    BaselineLevel
		checkID  string
		fields   []string
	}{
		{name: "linux securetty", template: TemplateLinux, level: BaselineLevel1, checkID: "5", fields: []string{"pts_rule_absent"}},
		{name: "linux syslog", template: TemplateLinux, level: BaselineLevel1, checkID: "9", fields: []string{"log_target_count"}},
		{name: "linux ftp banner", template: TemplateLinux, level: BaselineLevel1, checkID: "16", fields: []string{"banner_configured"}},
		{name: "linux ftp banner file", template: TemplateLinux, level: BaselineLevel1, checkID: "19", fields: []string{"banner_content_present"}},
		{name: "euler securetty", template: TemplateEulerOS, level: BaselineLevel1, checkID: "5", fields: []string{"pts_rule_absent"}},
		{name: "euler ssh access", template: TemplateEulerOS, level: BaselineLevel1, checkID: "9", fields: []string{"access_control_present"}},
		{name: "euler ssh banner adv", template: TemplateEulerOS, level: BaselineLevel3, checkID: "EUL-SSH-ADV-001", fields: []string{"banner_ok"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := liveUnixCheckResult(t, tc.template, tc.level, tc.checkID)
			for _, field := range tc.fields {
				if _, ok := lookupEvalValue(result.Eval, field); !ok {
					t.Fatalf("expected eval field %q for template=%s level=%s check=%s, got %#v", field, tc.template, tc.level, tc.checkID, result.Eval)
				}
			}
		})
	}
}

func liveUnixCheckResult(t *testing.T, template Template, level BaselineLevel, checkID string) benchmarkCheckResult {
	t.Helper()

	profile, err := nativeProfileForTemplateLevel(template, level)
	if err != nil {
		t.Fatalf("nativeProfileForTemplateLevel(%s, %s) error = %v", template, level, err)
	}

	found := false
	for _, check := range profile.checks {
		if check.id == checkID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("check %s not found in template=%s level=%s profile", checkID, template, level)
	}

	result, handled, err := collectUnixNativeCheck(context.Background(), template, checkID, &unixBenchmarkCollectorState{})
	if err != nil {
		t.Fatalf("collectUnixNativeCheck(%s, %s) error = %v", template, checkID, err)
	}
	if !handled {
		t.Fatalf("collectUnixNativeCheck(%s, %s) was not handled", template, checkID)
	}
	result = shapeUnixBenchmarkResult(template, result)
	result = shapeUnixAdvancedResult(result)
	return result
}
