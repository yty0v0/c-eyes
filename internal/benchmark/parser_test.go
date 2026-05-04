package benchmark

import (
	"path/filepath"
	"testing"
)

func TestParseXMLFileFixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		file     string
		template Template
		wantRows int
	}{
		{name: "windows", file: "windows.xml", template: TemplateWindows, wantRows: 2},
		{name: "linux", file: "linux.xml", template: TemplateLinux, wantRows: 2},
		{name: "euleros", file: "euleros.xml", template: TemplateEulerOS, wantRows: 1},
		{name: "kylin", file: "kylin.xml", template: TemplateKylin, wantRows: 1},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("testdata", tc.file)
			rows, err := parseXMLFile(path, tc.template, BaselineLevel1)
			if err != nil {
				t.Fatalf("parseXMLFile returned error: %v", err)
			}
			if len(rows) != tc.wantRows {
				t.Fatalf("expected %d rows, got %d", tc.wantRows, len(rows))
			}
			for _, row := range rows {
				if row.Template != string(tc.template) {
					t.Fatalf("expected template %q, got %q", tc.template, row.Template)
				}
				if row.ExecutionStatus == "" {
					t.Fatal("expected execution status")
				}
				if (row.Status == "pass" || row.Status == "fail") && !row.Evaluated {
					t.Fatalf("expected evaluated=true for status=%q", row.Status)
				}
			}
		})
	}
}

func TestParseXMLFileAppliesRuleMetadataForLinuxFamily(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		file     string
		template Template
	}{
		{name: "linux", file: "linux.xml", template: TemplateLinux},
		{name: "euleros", file: "euleros.xml", template: TemplateEulerOS},
		{name: "kylin", file: "kylin.xml", template: TemplateKylin},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rows, err := parseXMLFile(filepath.Join("testdata", tc.file), tc.template, BaselineLevel1)
			if err != nil {
				t.Fatalf("parseXMLFile returned error: %v", err)
			}
			for _, row := range rows {
				if row.CheckName == "" {
					t.Fatal("expected check_name to be populated")
				}
				if row.Category == "" {
					t.Fatal("expected category to be populated")
				}
				if row.ExecutionStatus == "" {
					t.Fatal("expected execution status to be populated")
				}
				if row.Status == "" {
					t.Fatal("expected status to be populated")
				}
			}
		})
	}
}

func TestSummarizeRows(t *testing.T) {
	t.Parallel()

	rows := []Row{
		{Status: "pass"},
		{Status: "pass"},
		{Status: "fail"},
		{Status: "unknown"},
	}

	summary := summarize(rows)
	if summary.Total != 4 {
		t.Fatalf("expected total=4, got %d", summary.Total)
	}
	if summary.Pass != 2 {
		t.Fatalf("expected pass=2, got %d", summary.Pass)
	}
	if summary.Fail != 1 {
		t.Fatalf("expected fail=1, got %d", summary.Fail)
	}
	if summary.Unknown != 1 {
		t.Fatalf("expected unknown=1, got %d", summary.Unknown)
	}
	if summary.Informational != 0 {
		t.Fatalf("expected informational=0, got %d", summary.Informational)
	}
	if summary.Pending != 1 {
		t.Fatalf("expected pending=1, got %d", summary.Pending)
	}
	if summary.Evaluated != 3 {
		t.Fatalf("expected evaluated=3, got %d", summary.Evaluated)
	}
	if summary.ComplianceRate <= 0.66 || summary.ComplianceRate >= 0.67 {
		t.Fatalf("expected compliance rate around 0.6667, got %f", summary.ComplianceRate)
	}
	if summary.CoverageRate <= 0.74 || summary.CoverageRate >= 0.76 {
		t.Fatalf("expected coverage rate around 0.75, got %f", summary.CoverageRate)
	}
	if summary.UnknownRate <= 0.24 || summary.UnknownRate >= 0.26 {
		t.Fatalf("expected unknown rate around 0.25, got %f", summary.UnknownRate)
	}
	if summary.InformationalRate != 0 {
		t.Fatalf("expected informational rate=0, got %f", summary.InformationalRate)
	}
	if summary.PendingRate <= 0.24 || summary.PendingRate >= 0.26 {
		t.Fatalf("expected pending rate around 0.25, got %f", summary.PendingRate)
	}
}

func TestSummarizeRowsAllUnknown(t *testing.T) {
	t.Parallel()

	rows := []Row{
		{Status: "unknown", StatusReason: "informational_check"},
		{Status: "UNKNOWN", StatusReason: "undetermined"},
	}

	summary := summarize(rows)
	if summary.Total != 2 {
		t.Fatalf("expected total=2, got %d", summary.Total)
	}
	if summary.Pass != 0 || summary.Fail != 0 {
		t.Fatalf("expected pass/fail to be zero, got pass=%d fail=%d", summary.Pass, summary.Fail)
	}
	if summary.Unknown != 2 {
		t.Fatalf("expected unknown=2, got %d", summary.Unknown)
	}
	if summary.Informational != 1 {
		t.Fatalf("expected informational=1, got %d", summary.Informational)
	}
	if summary.Pending != 1 {
		t.Fatalf("expected pending=1, got %d", summary.Pending)
	}
	if summary.Evaluated != 0 {
		t.Fatalf("expected evaluated=0, got %d", summary.Evaluated)
	}
	if summary.ComplianceRate != 0 {
		t.Fatalf("expected compliance rate=0, got %f", summary.ComplianceRate)
	}
	if summary.CoverageRate != 0 {
		t.Fatalf("expected coverage rate=0, got %f", summary.CoverageRate)
	}
	if summary.UnknownRate != 1 {
		t.Fatalf("expected unknown rate=1, got %f", summary.UnknownRate)
	}
	if summary.InformationalRate != 0.5 {
		t.Fatalf("expected informational rate=0.5, got %f", summary.InformationalRate)
	}
	if summary.PendingRate != 0.5 {
		t.Fatalf("expected pending rate=0.5, got %f", summary.PendingRate)
	}
}

func TestDeriveStatusNoPasswordFalsePositive(t *testing.T) {
	t.Parallel()

	status := deriveStatus(TemplateAuto, "X-001", "password policy configured")
	if status != "unknown" {
		t.Fatalf("expected unknown for password text, got %q", status)
	}
}

func TestDeriveStatusInformationalRuleOverridesGenericPass(t *testing.T) {
	t.Parallel()

	status := deriveStatus(TemplateWindows, "1", "Running")
	if status != "unknown" {
		t.Fatalf("expected unknown for informational check, got %q", status)
	}
}

func TestDeriveStatusAssessmentInformationalCheckMetadata(t *testing.T) {
	t.Parallel()

	assessment := deriveStatusAssessment(TemplateWindows, "1", "Running")
	if assessment.Status != "unknown" {
		t.Fatalf("expected unknown, got %q", assessment.Status)
	}
	if assessment.Evaluated {
		t.Fatal("expected informational check to be non-evaluated")
	}
	if assessment.StatusReason != "informational_check" {
		t.Fatalf("expected informational_check reason, got %q", assessment.StatusReason)
	}
	if assessment.ExecutionStatus != "ok" {
		t.Fatalf("expected execution status ok, got %q", assessment.ExecutionStatus)
	}
}

func TestDeriveStatusInformationalRuleTreatsDomainDisabledAsUnknown(t *testing.T) {
	t.Parallel()

	status := deriveStatus(TemplateWindows, "6", "Disabled Stopped")
	if status != "unknown" {
		t.Fatalf("expected unknown for informational domain value, got %q", status)
	}
}

func TestDeriveStatusInformationalRuleReportsExecutionFailure(t *testing.T) {
	t.Parallel()

	status := deriveStatus(TemplateWindows, "1", "failed to execute benchmark script")
	if status != "fail" {
		t.Fatalf("expected fail for explicit execution failure text, got %q", status)
	}

	assessment := deriveStatusAssessment(TemplateWindows, "1", "failed to execute benchmark script")
	if !assessment.Evaluated {
		t.Fatal("expected execution failure to be evaluated")
	}
	if assessment.StatusReason != "execution_error" {
		t.Fatalf("expected execution_error reason, got %q", assessment.StatusReason)
	}
	if assessment.ExecutionStatus != "error" {
		t.Fatalf("expected execution status error, got %q", assessment.ExecutionStatus)
	}
}

func TestDeriveStatusInformationalRulesAcrossFourTemplates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		template Template
		checkID  string
		actual   string
		want     string
	}{
		{name: "windows", template: TemplateWindows, checkID: "6", actual: "Auto Disabled", want: "unknown"},
		{name: "linux", template: TemplateLinux, checkID: "6", actual: "disabled", want: "unknown"},
		{name: "euleros", template: TemplateEulerOS, checkID: "6", actual: "disabled", want: "unknown"},
		{name: "kylin", template: TemplateKylin, checkID: "6", actual: "disabled", want: "unknown"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := deriveStatus(tc.template, tc.checkID, tc.actual)
			if got != tc.want {
				t.Fatalf("expected status=%q, got %q", tc.want, got)
			}
		})
	}
}

func TestDeriveStatusFallbackForUnmappedCheckID(t *testing.T) {
	t.Parallel()

	status := deriveStatus(TemplateWindows, "W-001", "Enabled")
	if status != "pass" {
		t.Fatalf("expected pass for unmapped check id fallback, got %q", status)
	}
}

func TestDeriveStatusAssessmentFallbackUnknownMetadata(t *testing.T) {
	t.Parallel()

	assessment := deriveStatusAssessment(TemplateAuto, "X-001", "manual inspection required")
	if assessment.Status != "unknown" {
		t.Fatalf("expected unknown, got %q", assessment.Status)
	}
	if assessment.Evaluated {
		t.Fatal("expected fallback unknown to be non-evaluated")
	}
	if assessment.StatusReason != "undetermined" {
		t.Fatalf("expected undetermined reason, got %q", assessment.StatusReason)
	}
	if assessment.ExecutionStatus != "ok" {
		t.Fatalf("expected execution status ok, got %q", assessment.ExecutionStatus)
	}
}
