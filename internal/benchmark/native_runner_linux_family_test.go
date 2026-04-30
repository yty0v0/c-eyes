package benchmark

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeCommandOutputUTF8LinuxFamilyTemplates(t *testing.T) {
	t.Parallel()

	raw := []byte("{\"value\":\"\u4e2d\u6587\u6d4b\u8bd5\"}\n")
	want := string(raw)

	for _, template := range []Template{TemplateLinux, TemplateEulerOS, TemplateKylin} {
		template := template
		t.Run(string(template), func(t *testing.T) {
			t.Parallel()

			got := normalizeCommandOutput(template, raw)
			if got != want {
				t.Fatalf("expected UTF-8 output to remain unchanged, want %q got %q", want, got)
			}
		})
	}
}

func TestExecuteNativeCheckCommandUTF8LinuxFamilyTemplates(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux shell runtime, got %s", runtime.GOOS)
	}

	check := nativeCheck{
		shell:   "sh",
		command: "printf '\\344\\270\\255\\346\\226\\207\\346\\265\\213\\350\\257\\225'",
	}
	want := "\u4e2d\u6587\u6d4b\u8bd5"

	for _, template := range []Template{TemplateLinux, TemplateEulerOS, TemplateKylin} {
		template := template
		t.Run(string(template), func(t *testing.T) {
			t.Parallel()

			got, err := executeNativeCheckCommand(context.Background(), template, check)
			if err != nil {
				t.Fatalf("executeNativeCheckCommand returned error: %v", err)
			}
			if got != want {
				t.Fatalf("expected %q, got %q", want, got)
			}
		})
	}
}

func TestRunNativeTemplateChecksLinuxFamilySmoke(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux shell runtime, got %s", runtime.GOOS)
	}

	for _, template := range []Template{TemplateLinux, TemplateEulerOS, TemplateKylin} {
		template := template
		t.Run(string(template), func(t *testing.T) {
			t.Parallel()

			workingRoot := t.TempDir()
			xmlPath, err := runNativeTemplateChecks(context.Background(), template, workingRoot, nil)
			if err != nil {
				t.Fatalf("runNativeTemplateChecks returned error: %v", err)
			}

			payload, err := os.ReadFile(xmlPath)
			if err != nil {
				t.Fatalf("read generated xml: %v", err)
			}
			if !utf8.Valid(payload) {
				t.Fatal("expected generated xml payload to be valid UTF-8")
			}
			if !strings.Contains(string(payload), "<?xml") {
				t.Fatal("expected generated xml header")
			}

			rows, err := parseXMLFile(xmlPath, template)
			if err != nil {
				t.Fatalf("parseXMLFile returned error: %v", err)
			}
			if len(rows) == 0 {
				t.Fatal("expected parsed rows from generated xml")
			}
			for _, row := range rows {
				if row.Template != string(template) {
					t.Fatalf("expected template %q, got %q", template, row.Template)
				}
			}
		})
	}
}

func TestScanUnixNativeBenchmarkLinuxFamilySmoke(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux runtime, got %s", runtime.GOOS)
	}

	for _, template := range []Template{TemplateLinux, TemplateEulerOS, TemplateKylin} {
		template := template
		t.Run(string(template), func(t *testing.T) {
			t.Parallel()

			result, handled, err := scanUnixNativeBenchmark(context.Background(), template, t.TempDir(), nil)
			if err != nil {
				t.Fatalf("scanUnixNativeBenchmark returned error: %v", err)
			}
			if !handled {
				t.Fatal("expected linux-family native benchmark path to be handled")
			}
			if result.Template != string(template) {
				t.Fatalf("expected template %q, got %q", template, result.Template)
			}
			if len(result.Rows) == 0 {
				t.Fatal("expected rows from linux-family native benchmark path")
			}
			for _, row := range result.Rows {
				if row.CheckName == "" {
					t.Fatal("expected check_name to be populated")
				}
				if row.ExecutionStatus == "" {
					t.Fatal("expected execution_status to be populated")
				}
			}
		})
	}
}

func TestLinuxFamilyRuleIDsExposeTemplateSpecificPrefixes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		template Template
		prefix   string
	}{
		{template: TemplateLinux, prefix: "LNX-"},
		{template: TemplateEulerOS, prefix: "EUL-"},
		{template: TemplateKylin, prefix: "KYL-"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.template), func(t *testing.T) {
			t.Parallel()

			rules, err := loadBenchmarkRuleSet(tc.template)
			if err != nil {
				t.Fatalf("loadBenchmarkRuleSet returned error: %v", err)
			}
			found := false
			for _, rule := range rules.Checks {
				if strings.HasPrefix(rule.ID, tc.prefix) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected at least one rule id with prefix %q", tc.prefix)
			}
		})
	}
}

func TestLinuxFamilyNativeBenchmarkCarriesTemplateSpecificRows(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux runtime, got %s", runtime.GOOS)
	}

	cases := []struct {
		template Template
		prefix   string
	}{
		{template: TemplateEulerOS, prefix: "EUL-"},
		{template: TemplateKylin, prefix: "KYL-"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.template), func(t *testing.T) {
			t.Parallel()

			result, handled, err := scanUnixNativeBenchmark(context.Background(), tc.template, t.TempDir(), nil)
			if err != nil {
				t.Fatalf("scanUnixNativeBenchmark returned error: %v", err)
			}
			if !handled {
				t.Fatal("expected template to be handled")
			}
			if result.Summary.Total == 0 {
				t.Fatal("expected non-empty summary")
			}
			if result.Summary.CoverageRate <= 0 {
				t.Fatalf("expected positive coverage rate, got %f", result.Summary.CoverageRate)
			}
			foundPrefix := false
			for _, row := range result.Rows {
				if row.CheckName == "" {
					t.Fatal("expected check name")
				}
				if row.Category == "" {
					t.Fatal("expected category")
				}
				if row.Actual == "" && row.Evidence == "" {
					t.Fatal("expected actual or evidence content")
				}
				if strings.HasPrefix(row.CheckID, tc.prefix) {
					foundPrefix = true
				}
			}
			if !foundPrefix {
				t.Fatalf("expected at least one row with prefix %q", tc.prefix)
			}
		})
	}
}

func TestLinuxNativeBenchmarkUnknownRowsAreOnlyInformational(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux runtime, got %s", runtime.GOOS)
	}

	result, handled, err := scanUnixNativeBenchmark(context.Background(), TemplateLinux, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("scanUnixNativeBenchmark returned error: %v", err)
	}
	if !handled {
		t.Fatal("expected linux template to be handled")
	}
	for _, row := range result.Rows {
		if row.Status != "unknown" {
			continue
		}
		if row.StatusReason != "informational_check" {
			t.Fatalf("expected unknown rows to be informational only, got check_id=%s reason=%s actual=%s", row.CheckID, row.StatusReason, row.Actual)
		}
	}
}
