package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"edrsystem/internal/eventlogscan"
	"edrsystem/internal/netscan"
	"edrsystem/internal/riskanalysis"
	"edrsystem/internal/sbom"
)

func TestParseGlobalCLIOptions(t *testing.T) {
	t.Parallel()

	opts, remaining, err := parseGlobalCLIOptions([]string{
		"hostscan",
		"--custom", "account",
		"-r",
		"--risk-mode", "local_only",
		"-o", "result.xlsx",
	})
	if err != nil {
		t.Fatalf("parseGlobalCLIOptions returned error: %v", err)
	}
	if !opts.RiskEnabled {
		t.Fatal("expected risk enabled")
	}
	if opts.RiskMode != "local_only" {
		t.Fatalf("expected risk mode local_only, got %q", opts.RiskMode)
	}
	if opts.OutputPath != "result.xlsx" {
		t.Fatalf("unexpected output path: %s", opts.OutputPath)
	}
	if len(remaining) != 3 {
		t.Fatalf("unexpected remaining args: %#v", remaining)
	}
}

func TestSanitizeModuleHelpTextRemovesLegacyOutputFlags(t *testing.T) {
	t.Parallel()

	raw := strings.Join([]string{
		"Usage:",
		"  c-eyes web-site-scan [options] [-output json|excel] [-excel out.xlsx]",
		"",
		"Options:",
		"  -excel string",
		"        Excel output file path (.xlsx)",
		"  -groups value",
		"        Filter by group IDs (comma-separated)",
		"  -output value",
		"        Output format (json or excel) (default json)",
		"",
	}, "\n")

	got := sanitizeModuleHelpText(raw)
	if strings.Contains(got, "-output") {
		t.Fatalf("expected sanitized help to remove -output, got: %s", got)
	}
	if strings.Contains(got, "-excel") {
		t.Fatalf("expected sanitized help to remove -excel, got: %s", got)
	}
	if !strings.Contains(got, "-groups value") {
		t.Fatalf("expected sanitized help to keep non-output flags, got: %s", got)
	}
}

func TestParseGlobalCLIOptionsOutputRequiresPath(t *testing.T) {
	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{
		"hostscan",
		"-o",
		"-r",
	})
	if err == nil {
		t.Fatal("expected -o without path error")
	}
	if !strings.Contains(err.Error(), "-o/--output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseGlobalCLIOptionsOutputEqualsRequiresPath(t *testing.T) {
	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{
		"hostscan",
		"-o=",
	})
	if err == nil {
		t.Fatal("expected -o= without path error")
	}
	if !strings.Contains(err.Error(), "-o/--output") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseGlobalCLIOptionsDefaultAutoOutput(t *testing.T) {
	t.Parallel()

	opts, remaining, err := parseGlobalCLIOptions([]string{
		"filescan",
	})
	if err != nil {
		t.Fatalf("parseGlobalCLIOptions returned error: %v", err)
	}
	if opts.OutputPath != autoExcelOutputSentinel {
		t.Fatalf("expected auto excel output sentinel by default, got %q", opts.OutputPath)
	}
	if len(remaining) != 1 || remaining[0] != "filescan" {
		t.Fatalf("unexpected remaining args: %#v", remaining)
	}
}

func TestParseGlobalCLIOptionsRiskModeRequiresRiskEnabled(t *testing.T) {
	t.Parallel()

	_, _, err := parseGlobalCLIOptions([]string{
		"filescan",
		"--risk-mode", "local_only",
	})
	if err == nil {
		t.Fatal("expected --risk-mode without -r/--riskanalyze to be rejected")
	}
	if !strings.Contains(err.Error(), "-r/--riskanalyze") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDetectOutputFormat(t *testing.T) {
	t.Parallel()

	format, err := detectOutputFormat("out.csv")
	if err != nil {
		t.Fatalf("detectOutputFormat returned error: %v", err)
	}
	if format != "csv" {
		t.Fatalf("expected csv, got %s", format)
	}

	if _, err := detectOutputFormat("out.txt"); err == nil {
		t.Fatal("expected invalid suffix error")
	}
}

func TestParseHostscanArgsMutualExclusion(t *testing.T) {
	t.Parallel()

	_, err := parseHostscanArgs([]string{"--custom", "account", "--all"})
	if err == nil {
		t.Fatal("expected mutual exclusion error")
	}
}

func TestParseHostscanArgsRequiresAllOrCustom(t *testing.T) {
	t.Parallel()

	_, err := parseHostscanArgs([]string{})
	if err == nil {
		t.Fatal("expected explicit module selection error")
	}
	if !strings.Contains(err.Error(), "requires either --all or --custom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyHostscanRiskModuleSelectionExplicitAllToRiskModules(t *testing.T) {
	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--all"})
	if err != nil {
		t.Fatalf("parseHostscanArgs returned error: %v", err)
	}
	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)
	if err != nil {
		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)
	}
	if len(adjusted.Modules) != len(hostscanRiskModuleOrder) {
		t.Fatalf("expected %d risk modules, got %d", len(hostscanRiskModuleOrder), len(adjusted.Modules))
	}
	for i, want := range hostscanRiskModuleOrder {
		if adjusted.Modules[i] != want {
			t.Fatalf("unexpected risk module at %d: got %s want %s", i, adjusted.Modules[i], want)
		}
	}
}

func TestApplyHostscanRiskModuleSelectionAllowsRiskCustomModules(t *testing.T) {
	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--custom", "process,kernel"})
	if err != nil {
		t.Fatalf("parseHostscanArgs returned error: %v", err)
	}
	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)
	if err != nil {
		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)
	}
	if len(adjusted.Modules) != 2 || adjusted.Modules[0] != "process" || adjusted.Modules[1] != "kernel" {
		t.Fatalf("expected risk custom modules to be unchanged, got %#v", adjusted.Modules)
	}
}

func TestApplyHostscanRiskModuleSelectionAllFlagToRiskModules(t *testing.T) {
	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--all"})
	if err != nil {
		t.Fatalf("parseHostscanArgs returned error: %v", err)
	}
	adjusted, err := applyHostscanRiskModuleSelection(parsed, true)
	if err != nil {
		t.Fatalf("applyHostscanRiskModuleSelection returned error: %v", err)
	}
	if len(adjusted.Modules) != len(hostscanRiskModuleOrder) {
		t.Fatalf("expected %d risk modules, got %d", len(hostscanRiskModuleOrder), len(adjusted.Modules))
	}
	for i, want := range hostscanRiskModuleOrder {
		if adjusted.Modules[i] != want {
			t.Fatalf("unexpected risk module at %d: got %s want %s", i, adjusted.Modules[i], want)
		}
	}
}

func TestApplyHostscanRiskModuleSelectionRejectsNonRiskCustomModules(t *testing.T) {
	t.Parallel()

	parsed, err := parseHostscanArgs([]string{"--custom", "account,process"})
	if err != nil {
		t.Fatalf("parseHostscanArgs returned error: %v", err)
	}
	_, err = applyHostscanRiskModuleSelection(parsed, true)
	if err == nil {
		t.Fatal("expected non-risk custom module error")
	}
	if !strings.Contains(err.Error(), "account") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseHostscanArgsMultiIntersectionValidation(t *testing.T) {
	t.Parallel()

	_, err := parseHostscanArgs([]string{"--custom", "account,process", "-hostname", "foo", "-uid", "1"})
	if err == nil {
		t.Fatal("expected non-intersection parameter error")
	}
}

func TestParseFilescanArgsConflict(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--custom", "site", "--scan-mode", "full"})
	if err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestParseFilescanArgsRequiresAllOrCustomForWebMode(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{})
	if err == nil {
		t.Fatal("expected explicit module selection error")
	}
	if !strings.Contains(err.Error(), "requires one of --all, --custom, or --scan-mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsAllSelectsAllWebModules(t *testing.T) {
	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--all"})
	if err != nil {
		t.Fatalf("parseFilescanArgs returned error: %v", err)
	}
	if parsed.IsLocalMode {
		t.Fatal("did not expect local mode")
	}
	if len(parsed.WebModules) != len(filescanWebModuleOrder) {
		t.Fatalf("expected %d web modules, got %d", len(filescanWebModuleOrder), len(parsed.WebModules))
	}
}

func TestParseFilescanArgsSupportsSoftwareModule(t *testing.T) {
	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--custom", "software"})
	if err != nil {
		t.Fatalf("parseFilescanArgs returned error: %v", err)
	}
	if parsed.IsLocalMode {
		t.Fatal("did not expect local mode")
	}
	if len(parsed.WebModules) != 1 || parsed.WebModules[0] != "software" {
		t.Fatalf("expected software module, got %#v", parsed.WebModules)
	}
}

func TestParseFilescanArgsSoftwareMultiModuleRejectsNonIntersectionParam(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--custom", "site,software", "-hostname", "node", "-name", "nginx"})
	if err == nil {
		t.Fatal("expected non-intersection error")
	}
	if !strings.Contains(err.Error(), "filescan multi-module mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsLocalPathRequired(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path"})
	if err == nil {
		t.Fatal("expected path required error")
	}
}

func TestParseFilescanArgsLocalPathPositional(t *testing.T) {
	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--scan-mode", "path", "/tmp/sample"})
	if err != nil {
		t.Fatalf("parseFilescanArgs returned error: %v", err)
	}
	if !parsed.IsLocalMode {
		t.Fatal("expected local mode")
	}
	if parsed.LocalMode != "path" {
		t.Fatalf("expected mode path, got %q", parsed.LocalMode)
	}
	if parsed.LocalPath != "/tmp/sample" {
		t.Fatalf("expected local path /tmp/sample, got %q", parsed.LocalPath)
	}
}

func TestParseFilescanArgsSmartRequiresScanMode(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--smart"})
	if err == nil {
		t.Fatal("expected smart flag validation error")
	}
	if !strings.Contains(err.Error(), "--smart can only be used with --scan-mode full|path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsSmartWithWebModeRejected(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--all", "--smart"})
	if err == nil {
		t.Fatal("expected smart + web mode conflict")
	}
	if !strings.Contains(err.Error(), "--smart can only be used with --scan-mode full|path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsLegacySmartModeRejected(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "smart"})
	if err == nil {
		t.Fatal("expected legacy smart mode rejected")
	}
	if !strings.Contains(err.Error(), "--scan-mode only supports full/path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsLocalFullSmart(t *testing.T) {
	t.Parallel()

	parsed, err := parseFilescanArgs([]string{"--scan-mode", "full", "--smart", "--max-targets", "10"})
	if err != nil {
		t.Fatalf("parseFilescanArgs returned error: %v", err)
	}
	if !parsed.IsLocalMode {
		t.Fatal("expected local mode")
	}
	if parsed.LocalMode != "full" {
		t.Fatalf("expected mode full, got %q", parsed.LocalMode)
	}
	if !parsed.LocalSmart {
		t.Fatal("expected LocalSmart=true")
	}
	if parsed.LocalMaxTarget != 10 {
		t.Fatalf("expected LocalMaxTarget=10, got %d", parsed.LocalMaxTarget)
	}
}

func TestParseFilescanArgsRejectScanPathFlag(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path", "--scan-path", "/tmp/sample"})
	if err == nil {
		t.Fatal("expected --scan-path rejected error")
	}
	if !strings.Contains(err.Error(), "--scan-path is no longer supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseFilescanArgsRejectWorkersFlag(t *testing.T) {
	t.Parallel()

	_, err := parseFilescanArgs([]string{"--scan-mode", "path", "/tmp/sample", "--workers", "4"})
	if err == nil {
		t.Fatal("expected --workers rejected error")
	}
	if !strings.Contains(err.Error(), "--workers is no longer supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseChainedRiskOptionsHostscanConstraint(t *testing.T) {
	t.Parallel()

	if _, err := parseChainedRiskOptions(nil, "deep", true, false); err == nil {
		t.Fatal("expected hostscan mode constraint error")
	}
	if _, err := parseChainedRiskOptions(nil, "local_only", true, false); err == nil {
		t.Fatal("expected hostscan to reject explicit local_only risk mode")
	}

	opts, err := parseChainedRiskOptions(nil, "", true, false)
	if err != nil {
		t.Fatalf("parseChainedRiskOptions returned error: %v", err)
	}
	if opts.Mode != "local_only" {
		t.Fatalf("expected local_only, got %s", opts.Mode)
	}
}

func TestParseChainedRiskOptionsHostscanRejectsCloudUpload(t *testing.T) {
	t.Parallel()

	_, err := parseChainedRiskOptions([]string{"-cloud-upload"}, "", true, false)
	if err == nil {
		t.Fatal("expected hostscan cloud-upload constraint error")
	}
	if !strings.Contains(err.Error(), "-cloud-upload") {
		t.Fatalf("expected cloud-upload error, got %v", err)
	}
}

func TestParseChainedRiskOptionsHostscanRejectsProcessMemoryWithoutProcessModule(t *testing.T) {
	t.Parallel()

	_, err := parseChainedRiskOptions([]string{"-process-memory"}, "", true, false)
	if err == nil {
		t.Fatal("expected hostscan process-memory constraint error")
	}
	if !strings.Contains(err.Error(), "-process-memory") {
		t.Fatalf("expected process-memory error, got %v", err)
	}
}

func TestParseChainedRiskOptionsHostscanAllowsProcessMemoryWithProcessModule(t *testing.T) {
	t.Parallel()

	opts, err := parseChainedRiskOptions([]string{"-process-memory"}, "", true, true)
	if err != nil {
		t.Fatalf("parseChainedRiskOptions returned error: %v", err)
	}
	if !opts.ProcessMemory {
		t.Fatal("expected process-memory=true")
	}
	if opts.Mode != "local_only" {
		t.Fatalf("expected local_only, got %s", opts.Mode)
	}
}

func TestParseChainedRiskOptionsFilescanAllowsCloudUpload(t *testing.T) {
	t.Parallel()

	opts, err := parseChainedRiskOptions([]string{"-cloud-upload"}, "", false, false)
	if err != nil {
		t.Fatalf("parseChainedRiskOptions returned error: %v", err)
	}
	if !opts.CloudUpload {
		t.Fatal("expected cloud-upload=true for filescan chained risk")
	}
}

func TestDedupeRowsExactMatchOnly(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{"a": 1, "b": "x"},
		{"b": "x", "a": 1},
		{"a": 1, "b": "y"},
	}
	got := dedupeRows(rows)
	if len(got) != 2 {
		t.Fatalf("expected 2 rows after dedupe, got %d", len(got))
	}
}

func TestAnySliceToMapRowsBatchMatchesLegacy(t *testing.T) {
	t.Parallel()

	type nested struct {
		Name  string   `json:"name"`
		Flags []string `json:"flags,omitempty"`
	}
	type row struct {
		ID     int            `json:"id"`
		Name   string         `json:"name"`
		Meta   nested         `json:"meta"`
		Ptr    *nested        `json:"ptr,omitempty"`
		Labels []string       `json:"labels"`
		Any    map[string]any `json:"any"`
		When   time.Time      `json:"when"`
	}

	fixed := time.Date(2026, 4, 17, 8, 0, 0, 0, time.UTC)
	input := []row{
		{
			ID:     1,
			Name:   "alpha",
			Meta:   nested{Name: "m1", Flags: []string{"x", "y"}},
			Ptr:    &nested{Name: "p1"},
			Labels: []string{"l1", "l2"},
			Any:    map[string]any{"k": "v", "n": 1},
			When:   fixed,
		},
		{
			ID:     2,
			Name:   "beta",
			Meta:   nested{Name: "m2"},
			Ptr:    nil,
			Labels: []string{},
			Any:    map[string]any{"k": "v2", "arr": []any{1, "x"}},
			When:   fixed.Add(time.Minute),
		},
	}

	got, err := anySliceToMapRows(input)
	if err != nil {
		t.Fatalf("anySliceToMapRows returned error: %v", err)
	}
	want, err := legacyAnySliceToMapRows(input)
	if err != nil {
		t.Fatalf("legacyAnySliceToMapRows returned error: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		t.Fatalf("batch conversion mismatch\n got=%s\nwant=%s", string(gotJSON), string(wantJSON))
	}

	gotPtr, err := anySliceToMapRows(&input)
	if err != nil {
		t.Fatalf("anySliceToMapRows(pointer) returned error: %v", err)
	}
	wantPtr, err := legacyAnySliceToMapRows(&input)
	if err != nil {
		t.Fatalf("legacyAnySliceToMapRows(pointer) returned error: %v", err)
	}
	if !reflect.DeepEqual(gotPtr, wantPtr) {
		gotJSON, _ := json.Marshal(gotPtr)
		wantJSON, _ := json.Marshal(wantPtr)
		t.Fatalf("batch conversion(pointer) mismatch\n got=%s\nwant=%s", string(gotJSON), string(wantJSON))
	}
}

func TestFlattenRowsAndHeadersMatchesLegacyHeaderCollection(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{
			"simple": "v1",
			"nested": map[string]any{
				"k1": "x",
				"k2": 2,
			},
		},
		{
			"simple": "v2",
			"arr":    []any{1, "a"},
		},
	}

	flatRows, headers := flattenRowsAndHeaders(rows)
	legacyHeaders := collectHeadersLegacy(rows)
	if !reflect.DeepEqual(headers, legacyHeaders) {
		t.Fatalf("headers mismatch: got=%v want=%v", headers, legacyHeaders)
	}
	if len(flatRows) != len(rows) {
		t.Fatalf("flat row size mismatch: got=%d want=%d", len(flatRows), len(rows))
	}
	for i := range rows {
		wantFlat := flattenRow(rows[i])
		if !reflect.DeepEqual(flatRows[i], wantFlat) {
			t.Fatalf("flat row mismatch at %d", i)
		}
	}
}

func TestRunUnifiedCLILegacyCommandRejected(t *testing.T) {
	t.Parallel()

	code := runUnifiedCLI([]string{"account", "scan"})
	if code == 0 {
		t.Fatal("expected non-zero exit code for legacy command")
	}
}

func TestRunUnifiedCLIFilescanHelpWithScanModePathDoesNotRequirePath(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"filescan",
		"--scan-mode", "path",
		"-h",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes filescan - Run a filescan task") {
		t.Fatalf("expected filescan help output, got: %s", output)
	}
	if strings.Contains(output, "requires a path") {
		t.Fatalf("did not expect path-required error in help mode, got: %s", output)
	}
}

func TestRunUnifiedCLIGlobalHelpForSBOMIgnoresInvalidArgs(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"-h",
		"sbom",
		"--format", "not-valid",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes sbom - Run an SBOM collection task") {
		t.Fatalf("expected sbom help output, got: %s", output)
	}
	if strings.Contains(output, "invalid argument:") {
		t.Fatalf("did not expect argument error in global help mode, got: %s", output)
	}
}

func TestRunUnifiedCLIGlobalHelpForEventlogIgnoresInvalidArgs(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"-h",
		"eventlog",
		"-last", "xyz",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes eventlog - Run an eventlog collection task") {
		t.Fatalf("expected eventlog help output, got: %s", output)
	}
	if strings.Contains(output, "invalid argument:") {
		t.Fatalf("did not expect argument error in global help mode, got: %s", output)
	}
}

func TestRunUnifiedCLIGlobalHelpForNetscanIgnoresInvalidArgs(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"-h",
		"netscan",
		"-scanMode", "BAD",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes netscan - Run an internal network discovery task") {
		t.Fatalf("expected netscan help output, got: %s", output)
	}
	if strings.Contains(output, "invalid argument:") {
		t.Fatalf("did not expect argument error in global help mode, got: %s", output)
	}
}

func TestRunUnifiedCLIGlobalHelpForHostscanIgnoresMissingSelection(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"-h",
		"hostscan",
		"-uid", "1",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes hostscan - Run a hostscan task") {
		t.Fatalf("expected hostscan help output, got: %s", output)
	}
	if strings.Contains(output, "requires either --all or --custom") {
		t.Fatalf("did not expect selection error in global help mode, got: %s", output)
	}
}

func TestRunUnifiedCLIFilescanRiskModeWithoutRiskAnalyzeRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"filescan",
		"--scan-mode", "path",
		t.TempDir(),
		"--risk-mode", "local_only",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "--risk-mode can only be used when -r/--riskanalyze is enabled") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIFilescanRiskFlagWithoutRiskAnalyzeRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"filescan",
		"--scan-mode", "full",
		"--smart",
		"-cloud-upload",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "-cloud-upload can only be used when -r/--riskanalyze is enabled") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIHostscanRiskFlagWithoutRiskAnalyzeRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"hostscan",
		"--custom", "process",
		"-process-memory",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "-process-memory can only be used when -r/--riskanalyze is enabled") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIRiskHelpWithShortFlag(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stderr = writer
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
		os.Stderr = originalStderr
	}()

	outputC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		outputC <- string(data)
	}()

	code := runUnifiedCLI([]string{"-r", "-h"})
	_ = writer.Close()
	output := <-outputC
	os.Stderr = originalStderr

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "c-eyes -r - Designated analysis source for anomaly analysis") {
		t.Fatalf("expected risk help output, got: %s", output)
	}
	if strings.Contains(output, "COMMANDS:") {
		t.Fatalf("expected not to print global help, got: %s", output)
	}
}

func TestRunUnifiedCLIHostscanRiskHelpShowsOnlyRiskModules(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stderr = writer
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
		os.Stderr = originalStderr
	}()

	outputC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		outputC <- string(data)
	}()

	code := runUnifiedCLI([]string{"hostscan", "-r", "-h"})
	_ = writer.Close()
	output := <-outputC
	os.Stderr = originalStderr

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "mode(Information scanning supported modules): account,usergroup,process,port,startup,scheduledtask,environment,kernel,database,application") {
		t.Fatalf("expected consolidated hostscan help output, got: %s", output)
	}
	if !strings.Contains(output, "OPTIONS(only -r enable can use):") {
		t.Fatalf("expected risk option section in consolidated help, got: %s", output)
	}
	if !strings.Contains(output, "--all") {
		t.Fatalf("expected --all option in hostscan help, got: %s", output)
	}
}

func TestRunUnifiedCLIFilescanHelpContainsAllOption(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stderr = writer
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
		os.Stderr = originalStderr
	}()

	outputC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		outputC <- string(data)
	}()

	code := runUnifiedCLI([]string{"filescan", "-h"})
	_ = writer.Close()
	output := <-outputC
	os.Stderr = originalStderr

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "--all") {
		t.Fatalf("expected --all option in filescan help, got: %s", output)
	}
	if !strings.Contains(output, "--smart") {
		t.Fatalf("expected --smart option in filescan help, got: %s", output)
	}
	if !strings.Contains(output, "only valid with --scan-mode full|path") {
		t.Fatalf("expected --smart condition note in filescan help, got: %s", output)
	}
	if !strings.Contains(output, "site,framework,jarpackage,software") {
		t.Fatalf("expected software in filescan module list, got: %s", output)
	}
}

func TestRunUnifiedCLIFilescanCustomSoftwareHelp(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stderr = writer
	defer func() {
		_ = writer.Close()
		_ = reader.Close()
		os.Stderr = originalStderr
	}()

	outputC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		outputC <- string(data)
	}()

	code := runUnifiedCLI([]string{"filescan", "--custom", "software", "-h"})
	_ = writer.Close()
	output := <-outputC
	os.Stderr = originalStderr

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(output, "-binPath") || !strings.Contains(output, "-configPath") {
		t.Fatalf("expected software module options, got: %s", output)
	}
}

func TestRunUnifiedCLIEventlogHelp(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"eventlog", "-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes eventlog - Run an eventlog collection task") {
		t.Fatalf("unexpected help output: %s", output)
	}
	if !strings.Contains(output, "-startTime <time>") || !strings.Contains(output, "-endTime <time>") {
		t.Fatalf("expected eventlog options in help output: %s", output)
	}
	if !strings.Contains(output, "-last <duration>") || !strings.Contains(output, "default: 24h") {
		t.Fatalf("expected eventlog last option in help output: %s", output)
	}
	if strings.Contains(output, "-since <time>") || strings.Contains(output, "-until <time>") {
		t.Fatalf("expected since/until options to be removed: %s", output)
	}
}

func TestRunUnifiedCLIRootHelpIncludesEventlog(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "eventlog") {
		t.Fatalf("expected root help to include eventlog command, got: %s", output)
	}
}

func TestRunUnifiedCLIRootHelpIncludesSBOM(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "sbom") {
		t.Fatalf("expected root help to include sbom command, got: %s", output)
	}
}

func TestRunUnifiedCLISBOMHelp(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "c-eyes sbom - Run an SBOM collection task") {
		t.Fatalf("unexpected help output: %s", output)
	}
	if !strings.Contains(output, "-p, --path <path>") {
		t.Fatalf("expected sbom path option in help output: %s", output)
	}
	if !strings.Contains(output, "--format <name>") || !strings.Contains(output, "xspdx-json|spdx-json") {
		t.Fatalf("expected sbom format options in help output: %s", output)
	}
	if !strings.Contains(output, "sbom is collection-only and does not support -r/--riskanalyze") {
		t.Fatalf("expected collection-only note in sbom help output: %s", output)
	}
	if !strings.Contains(output, "sbom requires -p/--path to define explicit scan scope.") {
		t.Fatalf("expected sbom required-path note in help output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRejectsRiskAnalyze(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-r"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support -r/--riskanalyze") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRejectsRiskOnlyFlag(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-cloud-upload"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support risk-analysis option") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRejectsCSVOutput(t *testing.T) {
	scanPath := t.TempDir()
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-p", scanPath, "-o", "sbom-result.csv"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "only supports .json") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRejectsXLSXOutput(t *testing.T) {
	scanPath := t.TempDir()
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-p", scanPath, "-o", "sbom-result.xlsx"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "only supports .json") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRejectsUnsupportedFormat(t *testing.T) {
	scanPath := t.TempDir()
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom", "-p", scanPath, "--format", "cyclonedx-json"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "xspdx-json|spdx-json") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLISBOMRequiresPath(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"sbom"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "-p/--path is required for sbom") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIRootHelpIncludesNetscan(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "netscan") {
		t.Fatalf("expected root help to include netscan command, got: %s", output)
	}
}

func TestRunUnifiedCLINetscanHelp(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"netscan", "-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "EXECUTE OPTIONS:") || !strings.Contains(output, "FILTER OPTIONS:") {
		t.Fatalf("expected netscan help sections, got: %s", output)
	}
	if !strings.Contains(output, "A(ARP),ICP(ICMP-PING),ICA(ICMP-ADDRESSMASK),ICT(ICMP-TIMESTAMP),T(TCP-CONNECT),TS(TCP-SYN),U(UDP),N(NETBIOS),O(OXID)") {
		t.Fatalf("expected mode list in netscan help, got: %s", output)
	}
	if !strings.Contains(output, "-reachableSegments") {
		t.Fatalf("expected reachableSegments execute option in netscan help, got: %s", output)
	}
	if !strings.Contains(output, "use -target/-targetFile for strict scan scope control") {
		t.Fatalf("expected strict scope guidance in netscan help, got: %s", output)
	}
}

func TestRunUnifiedCLINetscanRejectsRiskAnalyze(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"netscan", "-r"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support -r/--riskanalyze") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLINetscanRejectsRiskOnlyFlag(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"netscan", "-cloud-upload"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support risk-analysis option") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestParseNetscanArgs(t *testing.T) {
	t.Parallel()

	parsed, err := parseNetscanArgs([]string{
		"-target", "192.168.1.1-10",
		"-scanMode", "ICP,T,U",
		"-reachableSegments",
		"-tcpPorts", "22,445",
		"-udpPorts", "53,161",
		"-maxTargets", "128",
		"-pps", "120",
		"-workers", "8",
		"-assetStatus", "unmanaged",
		"-sortBy", "lastSeen",
		"-sortOrder", "desc",
	})
	if err != nil {
		t.Fatalf("parseNetscanArgs returned error: %v", err)
	}
	if parsed.ShowHelp {
		t.Fatal("did not expect help mode")
	}
	if parsed.Params.Target != "192.168.1.1-10" {
		t.Fatalf("unexpected target: %s", parsed.Params.Target)
	}
	if len(parsed.Params.ScanModes) != 3 {
		t.Fatalf("expected 3 scan modes, got %d", len(parsed.Params.ScanModes))
	}
	if !parsed.Params.ReachableSegments {
		t.Fatal("expected reachableSegments=true")
	}
	if parsed.Params.ScanModes[0] != netscan.ModeICMPEcho || parsed.Params.ScanModes[1] != netscan.ModeTCPConnect || parsed.Params.ScanModes[2] != netscan.ModeUDP {
		t.Fatalf("unexpected scan modes: %#v", parsed.Params.ScanModes)
	}
	if len(parsed.Params.TCPPorts) != 2 || parsed.Params.TCPPorts[0] != 22 || parsed.Params.TCPPorts[1] != 445 {
		t.Fatalf("unexpected tcp ports: %#v", parsed.Params.TCPPorts)
	}
	if len(parsed.Params.UDPPorts) != 2 || parsed.Params.UDPPorts[0] != 53 || parsed.Params.UDPPorts[1] != 161 {
		t.Fatalf("unexpected udp ports: %#v", parsed.Params.UDPPorts)
	}
}

func TestParseSBOMArgsRequiresPath(t *testing.T) {
	t.Parallel()

	_, err := parseSBOMArgs([]string{})
	if err == nil {
		t.Fatal("expected missing path error")
	}
	if !strings.Contains(err.Error(), "-p/--path is required for sbom") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseSBOMArgsAcceptsSPDXJSON(t *testing.T) {
	t.Parallel()

	scanPath := filepath.Join("tmp", "sbom")
	parsed, err := parseSBOMArgs([]string{"--path", scanPath, "--format", sbom.FormatSPDXJSON})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.Path != scanPath {
		t.Fatalf("expected path %q, got %q", scanPath, parsed.Path)
	}
	if parsed.Format != sbom.FormatSPDXJSON {
		t.Fatalf("expected format %q, got %q", sbom.FormatSPDXJSON, parsed.Format)
	}
}

func TestParseSBOMArgsAcceptsLongPathFlag(t *testing.T) {
	t.Parallel()

	scanPath := filepath.Join("tmp", "sbom")
	parsed, err := parseSBOMArgs([]string{"--path", scanPath})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.Path != scanPath {
		t.Fatalf("expected path %q, got %q", scanPath, parsed.Path)
	}
}

func TestParseSBOMArgsAcceptsShortPathFlag(t *testing.T) {
	t.Parallel()

	scanPath := filepath.Join("tmp", "sbom")
	parsed, err := parseSBOMArgs([]string{"-p", scanPath})
	if err != nil {
		t.Fatalf("parseSBOMArgs returned error: %v", err)
	}
	if parsed.Path != scanPath {
		t.Fatalf("expected path %q, got %q", scanPath, parsed.Path)
	}
}

func TestParseSBOMArgsRejectsUnsupportedFormat(t *testing.T) {
	t.Parallel()

	_, err := parseSBOMArgs([]string{"--path", filepath.Join("tmp", "sbom"), "--format", "cyclonedx-json"})
	if err == nil {
		t.Fatal("expected unsupported format error")
	}
	if !strings.Contains(err.Error(), "xspdx-json|spdx-json") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseNetscanArgsInvalidPorts(t *testing.T) {
	t.Parallel()

	_, err := parseNetscanArgs([]string{"-tcpPorts", "22,70000"})
	if err == nil {
		t.Fatal("expected invalid port error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tcpports") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseNetscanArgsReachableSegmentsDefaultsFalse(t *testing.T) {
	t.Parallel()

	parsed, err := parseNetscanArgs([]string{"-target", "192.168.1.10"})
	if err != nil {
		t.Fatalf("parseNetscanArgs returned error: %v", err)
	}
	if parsed.Params.ReachableSegments {
		t.Fatal("expected reachableSegments=false by default")
	}
}

func TestParseNetscanArgsReachableSegmentsUsesDedicatedDefaults(t *testing.T) {
	t.Parallel()

	parsed, err := parseNetscanArgs([]string{"-reachableSegments"})
	if err != nil {
		t.Fatalf("parseNetscanArgs returned error: %v", err)
	}
	if !parsed.Params.ReachableSegments {
		t.Fatal("expected reachableSegments=true")
	}
	if !parsed.ReachableDefaultScanModeApplied {
		t.Fatal("expected reachable scanMode default marker")
	}
	if !parsed.ReachableDefaultMaxTargetsApplied {
		t.Fatal("expected reachable maxTargets default marker")
	}
	if len(parsed.Params.ScanModes) != 2 {
		t.Fatalf("expected 2 reachable default scan modes, got %d", len(parsed.Params.ScanModes))
	}
	if parsed.Params.ScanModes[0] != netscan.ModeICMPEcho || parsed.Params.ScanModes[1] != netscan.ModeTCPConnect {
		t.Fatalf("unexpected reachable default scan modes: %#v", parsed.Params.ScanModes)
	}
	if parsed.Params.MaxTargets != reachableDefaultMaxTargets {
		t.Fatalf("expected reachable default maxTargets=%d, got %d", reachableDefaultMaxTargets, parsed.Params.MaxTargets)
	}
}

func TestParseNetscanArgsReachableSegmentsKeepsExplicitValues(t *testing.T) {
	t.Parallel()

	parsed, err := parseNetscanArgs([]string{
		"-reachableSegments",
		"-scanMode", "A,U",
		"-maxTargets", "777",
	})
	if err != nil {
		t.Fatalf("parseNetscanArgs returned error: %v", err)
	}
	if parsed.ReachableDefaultScanModeApplied {
		t.Fatal("did not expect reachable scanMode default marker when -scanMode is explicit")
	}
	if parsed.ReachableDefaultMaxTargetsApplied {
		t.Fatal("did not expect reachable maxTargets default marker when -maxTargets is explicit")
	}
	if len(parsed.Params.ScanModes) != 2 {
		t.Fatalf("expected 2 explicit scan modes, got %d", len(parsed.Params.ScanModes))
	}
	if parsed.Params.ScanModes[0] != netscan.ModeARP || parsed.Params.ScanModes[1] != netscan.ModeUDP {
		t.Fatalf("unexpected explicit scan modes: %#v", parsed.Params.ScanModes)
	}
	if parsed.Params.MaxTargets != 777 {
		t.Fatalf("expected maxTargets=777, got %d", parsed.Params.MaxTargets)
	}
}

func TestRunUnifiedCLIEventlogRejectsRiskAnalyze(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"eventlog", "-r"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support -r/--riskanalyze") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIEventlogRejectsRiskOnlyFlag(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{"eventlog", "-cloud-upload"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "does not support risk-analysis option") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestParseEventlogArgsDefaultsToLast24h(t *testing.T) {
	t.Parallel()

	parsed, err := parseEventlogArgs([]string{})
	if err != nil {
		t.Fatalf("parseEventlogArgs returned error: %v", err)
	}
	if parsed.Params.StartTime <= 0 || parsed.Params.EndTime <= 0 {
		t.Fatalf("expected positive default time range, got start=%d end=%d", parsed.Params.StartTime, parsed.Params.EndTime)
	}
	if got := parsed.Params.EndTime - parsed.Params.StartTime; got != (24 * time.Hour).Milliseconds() {
		t.Fatalf("expected default 24h window, got %d ms", got)
	}
}

func TestParseEventlogArgsSupportsModernTimeFlags(t *testing.T) {
	t.Parallel()

	parsed, err := parseEventlogArgs([]string{
		"-startTime", "2026-04-15 00:00:00",
		"-endTime", "2026-04-16 00:00:00",
	})
	if err != nil {
		t.Fatalf("parseEventlogArgs returned error: %v", err)
	}
	if got := parsed.Params.EndTime - parsed.Params.StartTime; got != (24 * time.Hour).Milliseconds() {
		t.Fatalf("expected 24h range, got %d ms", got)
	}
}

func TestParseEventlogArgsSupportsLastDays(t *testing.T) {
	t.Parallel()

	parsed, err := parseEventlogArgs([]string{"-last", "7d"})
	if err != nil {
		t.Fatalf("parseEventlogArgs returned error: %v", err)
	}
	if got := parsed.Params.EndTime - parsed.Params.StartTime; got != (7 * 24 * time.Hour).Milliseconds() {
		t.Fatalf("expected 7d range, got %d ms", got)
	}
}

func TestParseEventlogArgsRejectsStartTimeWithLast(t *testing.T) {
	t.Parallel()

	_, err := parseEventlogArgs([]string{
		"-startTime", "1000",
		"-last", "1h",
	})
	if err == nil {
		t.Fatal("expected startTime with last conflict error")
	}
	if !strings.Contains(err.Error(), "cannot be used with -last") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunUnifiedCLIEventlogSinceFlagRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"eventlog",
		"-since", "2026-04-16",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "flag provided but not defined") || !strings.Contains(output, "since") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIEventlogInvalidRangeRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"eventlog",
		"-startTime", "2026-04-16 23:59:59",
		"-endTime", "2026-04-16 00:00:00",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "startTime cannot be greater than endTime") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestRunUnifiedCLIEventlogInvalidPagingRejected(t *testing.T) {
	code, output := runUnifiedCLIWithCapturedStderr(t, []string{
		"eventlog",
		"-pageSize", "500",
	})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d (output: %s)", code, output)
	}
	if !strings.Contains(output, "pageSize must be between 1 and 200") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestEmitOutputEventlogEnvelopeAcrossFormats(t *testing.T) {
	t.Parallel()

	host := "node-a"
	procName := "cmd.exe"
	message := "process started"
	payload := eventlogscan.ScanResult{
		Total:    1,
		PageNo:   1,
		PageSize: 20,
		HasMore:  false,
		Rows: []eventlogscan.EventRow{
			{
				LogID:          "evt_1",
				Timestamp:      1710000000000,
				OSType:         "windows",
				Source:         "system",
				EventType:      "process",
				EventLevel:     "info",
				EventCode:      "1000",
				EventAction:    "start",
				Result:         "success",
				Hostname:       &host,
				ProcessName:    &procName,
				InternalIPList: []string{},
				ExternalIPList: []string{},
				Message:        &message,
			},
		},
	}

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "eventlog.json")
	csvPath := filepath.Join(dir, "eventlog.csv")
	xlsxPath := filepath.Join(dir, "eventlog.xlsx")

	if err := emitOutput(payload, jsonPath); err != nil {
		t.Fatalf("emitOutput json returned error: %v", err)
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json output failed: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json unmarshal failed: %v", err)
	}
	for _, key := range []string{"total", "pageNo", "pageSize", "hasMore", "rows"} {
		if _, ok := parsed[key]; !ok {
			t.Fatalf("expected json envelope key %q, got: %#v", key, parsed)
		}
	}

	if err := emitOutput(payload, csvPath); err != nil {
		t.Fatalf("emitOutput csv returned error: %v", err)
	}
	if info, err := os.Stat(csvPath); err != nil || info.Size() == 0 {
		t.Fatalf("expected csv output file, err=%v size=%d", err, fileSizeOrZero(info))
	}

	if err := emitOutput(payload, xlsxPath); err != nil {
		t.Fatalf("emitOutput xlsx returned error: %v", err)
	}
	if info, err := os.Stat(xlsxPath); err != nil || info.Size() == 0 {
		t.Fatalf("expected xlsx output file, err=%v size=%d", err, fileSizeOrZero(info))
	}
}

func TestEmitOutputPermissionDeniedFallsBackToStdoutJSON(t *testing.T) {
	t.Parallel()

	payload := scanAggregateResult{
		Total: 1,
		Rows: []map[string]any{
			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	promptCalled := false
	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{
		json: func(path string, payload any) error { return nil },
		csv:  func(path string, rows []map[string]any) error { return nil },
		xlsx: func(path string, rows []map[string]any) error { return os.ErrPermission },
	}, &stdout, &stderr, strings.NewReader("y\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {
		promptCalled = true
		return true, nil
	})
	if err != nil {
		t.Fatalf("expected fallback success, got error: %v", err)
	}
	if !promptCalled {
		t.Fatal("expected permission fallback prompt to be called")
	}

	stdoutStr := stdout.String()
	if !strings.Contains(stdoutStr, "\"total\": 1") || !strings.Contains(stdoutStr, "\"rows\"") {
		t.Fatalf("expected fallback JSON in stdout, got: %s", stdoutStr)
	}
}

func TestEmitOutputPermissionDeniedPromptDeclineReturnsError(t *testing.T) {
	t.Parallel()

	payload := scanAggregateResult{
		Total: 1,
		Rows: []map[string]any{
			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{
		json: func(path string, payload any) error { return nil },
		csv:  func(path string, rows []map[string]any) error { return nil },
		xlsx: func(path string, rows []map[string]any) error { return os.ErrPermission },
	}, &stdout, &stderr, strings.NewReader("n\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("expected permission error when user declines fallback")
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout fallback output, got: %s", stdout.String())
	}
}

func TestEmitOutputNonPermissionErrorDoesNotFallback(t *testing.T) {
	t.Parallel()

	payload := scanAggregateResult{
		Total: 1,
		Rows: []map[string]any{
			{"module": "process", "name": "cmd.exe"},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	writeErr := errors.New("disk full")
	err := emitOutputWithPrompt(payload, "result.xlsx", outputWriteSet{
		json: func(path string, payload any) error { return nil },
		csv:  func(path string, rows []map[string]any) error { return nil },
		xlsx: func(path string, rows []map[string]any) error { return writeErr },
	}, &stdout, &stderr, strings.NewReader("y\n"), func(outputPath string, writeErr error, stdin io.Reader, stderr io.Writer) (bool, error) {
		return true, nil
	})
	if err == nil {
		t.Fatal("expected non-permission error to be returned")
	}
	if !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("expected disk full error, got: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout fallback output, got: %s", stdout.String())
	}
}

func TestWriteShardedXLSXFilesSplitsRowsAndNamesParts(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{"id": 1},
		{"id": 2},
		{"id": 3},
		{"id": 4},
		{"id": 5},
	}

	basePath := filepath.Join(t.TempDir(), "result.xlsx")
	calledPaths := make([]string, 0)
	calledSizes := make([]int, 0)

	paths, err := writeShardedXLSXFiles(basePath, rows, 2, func(path string, partRows []map[string]any) error {
		calledPaths = append(calledPaths, path)
		calledSizes = append(calledSizes, len(partRows))
		return nil
	})
	if err != nil {
		t.Fatalf("writeShardedXLSXFiles returned error: %v", err)
	}

	wantPaths := []string{
		filepath.Join(filepath.Dir(basePath), "result_part1.xlsx"),
		filepath.Join(filepath.Dir(basePath), "result_part2.xlsx"),
		filepath.Join(filepath.Dir(basePath), "result_part3.xlsx"),
	}
	wantSizes := []int{2, 2, 1}

	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("unexpected written paths: got=%v want=%v", paths, wantPaths)
	}
	if !reflect.DeepEqual(calledPaths, wantPaths) {
		t.Fatalf("unexpected writer called paths: got=%v want=%v", calledPaths, wantPaths)
	}
	if !reflect.DeepEqual(calledSizes, wantSizes) {
		t.Fatalf("unexpected shard sizes: got=%v want=%v", calledSizes, wantSizes)
	}
}

func TestWriteShardedXLSXFilesSinglePartKeepsOriginalName(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{"id": 1},
		{"id": 2},
	}

	basePath := filepath.Join(t.TempDir(), "result.xlsx")
	calledPaths := make([]string, 0)

	paths, err := writeShardedXLSXFiles(basePath, rows, 10, func(path string, partRows []map[string]any) error {
		calledPaths = append(calledPaths, path)
		return nil
	})
	if err != nil {
		t.Fatalf("writeShardedXLSXFiles returned error: %v", err)
	}

	wantPaths := []string{basePath}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("unexpected written paths: got=%v want=%v", paths, wantPaths)
	}
	if !reflect.DeepEqual(calledPaths, wantPaths) {
		t.Fatalf("unexpected writer called paths: got=%v want=%v", calledPaths, wantPaths)
	}
}

func TestEmitGeneratedFileHintsForShardedOutput(t *testing.T) {
	t.Parallel()

	paths := []string{"result_part1.xlsx", "result_part2.xlsx"}

	var stderr bytes.Buffer
	emitGeneratedFileHints(&stderr, paths, false)
	out := stderr.String()
	if !strings.Contains(out, "generated file: result_part1.xlsx") {
		t.Fatalf("expected first generated file hint, got: %s", out)
	}
	if !strings.Contains(out, "generated file: result_part2.xlsx") {
		t.Fatalf("expected second generated file hint, got: %s", out)
	}
}

func TestValidateXLSXShapeLimits(t *testing.T) {
	t.Parallel()

	if err := validateXLSXShape(xlsxMaxRows-1, xlsxMaxColumns); err != nil {
		t.Fatalf("expected limits to pass, got: %v", err)
	}

	if err := validateXLSXShape(xlsxMaxRows, 1); err == nil || !strings.Contains(err.Error(), "row limit") {
		t.Fatalf("expected row limit error, got: %v", err)
	}

	if err := validateXLSXShape(1, xlsxMaxColumns+1); err == nil || !strings.Contains(err.Error(), "column limit") {
		t.Fatalf("expected column limit error, got: %v", err)
	}
}

func TestCompactWriteErrorMessageTrimsDuplicatedOpenPrefix(t *testing.T) {
	t.Parallel()

	path := `D:\tmp\result.xlsx`
	err := fmt.Errorf("open %s: Access is denied.", path)
	got := compactWriteErrorMessage(path, err)
	if got != "Access is denied." {
		t.Fatalf("expected trimmed message, got %q", got)
	}
}

func TestCompactWriteErrorMessageFallsBackToRawError(t *testing.T) {
	t.Parallel()

	err := errors.New("disk full")
	got := compactWriteErrorMessage(`D:\tmp\result.xlsx`, err)
	if got != "disk full" {
		t.Fatalf("expected raw message fallback, got %q", got)
	}
}

func TestCompactScanTargetErrorMessageTrimsOpenPrefix(t *testing.T) {
	t.Parallel()

	path := `D:\secure\secret.dll`
	err := fmt.Errorf("open %s: Access is denied.", path)
	got := compactScanTargetErrorMessage(path, err)
	if got != "Access is denied." {
		t.Fatalf("expected trimmed message, got %q", got)
	}
}

func TestCompactScanTargetErrorMessageFallsBackToRaw(t *testing.T) {
	t.Parallel()

	err := errors.New("input/output timeout")
	got := compactScanTargetErrorMessage(`D:\secure\secret.dll`, err)
	if got != "input/output timeout" {
		t.Fatalf("expected raw message fallback, got %q", got)
	}
}

func TestExecuteHostscanSkipsFailedModuleAndContinues(t *testing.T) {
	t.Parallel()

	parsed := hostscanParseResult{
		Modules:    []string{"invalid-hostscan-module"},
		MultiMode:  false,
		ModuleArgs: nil,
	}

	var progressOut bytes.Buffer
	result, records, err := executeHostscan(parsed, false, 0, newTerminalProgress(&progressOut, "hostscan"))
	if err != nil {
		t.Fatalf("expected nil error for module failure, got: %v", err)
	}
	if result.Total != 0 || len(result.Rows) != 0 {
		t.Fatalf("expected empty aggregated result, got total=%d rows=%d", result.Total, len(result.Rows))
	}
	if len(records) != 0 {
		t.Fatalf("expected no risk records, got %d", len(records))
	}

	output := progressOut.String()
	if !strings.Contains(output, "[WARN] hostscan module invalid-hostscan-module failed:") {
		t.Fatalf("expected failed-module log line, got: %s", output)
	}
	if !strings.Contains(output, "[WARN] hostscan skipped 1 failed module(s)") {
		t.Fatalf("expected skipped warning line, got: %s", output)
	}
}

func TestExecuteFilescanWebModeSkipsFailedModuleAndContinues(t *testing.T) {
	t.Parallel()

	parsed := filescanParseResult{
		WebModules: []string{"invalid-filescan-module"},
		ModuleArgs: nil,
	}

	var progressOut bytes.Buffer
	result, records, err := executeFilescanWebMode(parsed, newTerminalProgress(&progressOut, "filescan"))
	if err != nil {
		t.Fatalf("expected nil error for module failure, got: %v", err)
	}
	if result.Total != 0 || len(result.Rows) != 0 {
		t.Fatalf("expected empty aggregated result, got total=%d rows=%d", result.Total, len(result.Rows))
	}
	if len(records) != 0 {
		t.Fatalf("expected no risk records, got %d", len(records))
	}

	output := progressOut.String()
	if !strings.Contains(output, "[WARN] filescan module invalid-filescan-module failed:") {
		t.Fatalf("expected failed-module log line, got: %s", output)
	}
	if !strings.Contains(output, "[WARN] filescan skipped 1 failed module(s)") {
		t.Fatalf("expected skipped warning line, got: %s", output)
	}
}

func TestMapRowsToRiskRecordsWithPathCandidates(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{
			"hostname": "node-a",
			"execPath": "/usr/bin/python3",
			"conf":     "/etc/crontab",
		},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath", "conf"})
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	got := map[string]bool{}
	for _, record := range records {
		if record.Raw["target_type"] != "file" {
			t.Fatalf("expected target_type=file, got %#v", record.Raw["target_type"])
		}
		path, _ := record.Raw["target_path"].(string)
		got[path] = true
	}
	if !got["/usr/bin/python3"] || !got["/etc/crontab"] {
		t.Fatalf("unexpected target paths: %#v", got)
	}
}

func TestMapRowsToRiskRecordsWithPathCandidatesFallback(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{"hostname": "node-a", "name": "service-a"},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"execPath"})
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Raw["target_type"] != "file" {
		t.Fatalf("expected target_type=file, got %#v", records[0].Raw["target_type"])
	}
	if _, ok := records[0].Raw["target_path"]; ok {
		t.Fatalf("expected no target_path, got %#v", records[0].Raw["target_path"])
	}
}

func TestMapRowsToRiskRecordsWithSoftwarePathCandidates(t *testing.T) {
	t.Parallel()

	rows := []map[string]any{
		{
			"name":       "nginx",
			"binPath":    "/usr/sbin/nginx",
			"configPath": "/etc/nginx/nginx.conf",
		},
	}

	records := mapRowsToRiskRecordsWithPathCandidates(rows, "file", []string{"binPath", "configPath"})
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	got := map[string]bool{}
	for _, record := range records {
		if record.Raw["target_type"] != "file" {
			t.Fatalf("expected target_type=file, got %#v", record.Raw["target_type"])
		}
		path, _ := record.Raw["target_path"].(string)
		got[path] = true
	}
	if !got["/usr/sbin/nginx"] || !got["/etc/nginx/nginx.conf"] {
		t.Fatalf("unexpected target paths: %#v", got)
	}
}

func TestAnalyzeRiskResultsEmptyOverrideRecords(t *testing.T) {
	t.Parallel()

	results, err := analyzeRiskResults(riskOptions{Mode: "local_only"}, []riskanalysis.ScanRecord{}, nil)
	if err != nil {
		t.Fatalf("analyzeRiskResults returned error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected empty results, got %d", len(results))
	}
}

func TestClassifyRiskSeverityBand(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   riskanalysis.RiskAssessment
		want riskSeverityBand
	}{
		{
			name: "critical is high",
			in: riskanalysis.RiskAssessment{
				RiskLevel: riskanalysis.RiskLevelCritical,
			},
			want: riskSeverityHigh,
		},
		{
			name: "medium level",
			in: riskanalysis.RiskAssessment{
				RiskLevel: riskanalysis.RiskLevelMedium,
			},
			want: riskSeverityMedium,
		},
		{
			name: "low level",
			in: riskanalysis.RiskAssessment{
				RiskLevel: riskanalysis.RiskLevelLow,
			},
			want: riskSeverityLow,
		},
		{
			name: "fallback by score",
			in: riskanalysis.RiskAssessment{
				RiskLevel: "unknown",
				RiskScore: 88,
			},
			want: riskSeverityHigh,
		},
		{
			name: "none by score",
			in: riskanalysis.RiskAssessment{
				RiskLevel: "unknown",
				RiskScore: 10,
			},
			want: riskSeverityNone,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyRiskSeverityBand(tc.in); got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestFormatRiskStreamLineIncludesBasicInfo(t *testing.T) {
	t.Parallel()

	size := int64(2048)
	result := riskanalysis.AnalysisResult{
		TargetPath: "C:\\test\\a.exe",
		FileSize:   &size,
		Hashes: riskanalysis.Hashes{
			Sha256: "abc123",
		},
		LocalAnalysis: &riskanalysis.LocalAnalysis{
			YaraResults: []riskanalysis.YaraRuleMatch{{RuleName: "Test.Rule"}},
		},
	}

	line := formatRiskStreamLine(result, riskSeverityHigh, false)
	if !strings.Contains(line, "[HIGH]") {
		t.Fatalf("expected high label, got %q", line)
	}
	if !strings.Contains(line, "path=C:\\test\\a.exe") {
		t.Fatalf("expected path, got %q", line)
	}
	if !strings.Contains(line, "size=2.0 KB") {
		t.Fatalf("expected formatted size, got %q", line)
	}
	if !strings.Contains(line, "sha256=abc123") {
		t.Fatalf("expected sha256, got %q", line)
	}
	if !strings.Contains(line, "rule=Test.Rule") {
		t.Fatalf("expected rule, got %q", line)
	}
}

func TestCompactSHA256(t *testing.T) {
	t.Parallel()

	full := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := compactSHA256(full)
	if got != "0123456789ab...89abcdef" {
		t.Fatalf("unexpected compact hash: %q", got)
	}
}

func TestCompactMiddleTruncatesLongPath(t *testing.T) {
	t.Parallel()

	value := "C:\\very\\long\\path\\to\\something\\binary\\that\\is\\too\\long\\sample.exe"
	got := compactMiddle(value, 36)
	if len([]rune(got)) > 36 {
		t.Fatalf("expected compact length <= 36, got %d (%q)", len([]rune(got)), got)
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("expected compact marker, got %q", got)
	}
}

func TestNextAutoExcelOutputPathEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	got, err := nextAutoExcelOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result.xlsx")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNextAutoExcelOutputPathWithResultOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "result.xlsx"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write result.xlsx: %v", err)
	}
	got, err := nextAutoExcelOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result1.xlsx")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNextAutoExcelOutputPathWithResultOneUsesMaxPlusOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	seed := []string{"result.xlsx", "result1.xlsx", "result2.xlsx", "result9.xlsx"}
	for _, name := range seed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	got, err := nextAutoExcelOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoExcelOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result10.xlsx")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNextAutoJSONOutputPathEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	got, err := nextAutoJSONOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result.json")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNextAutoJSONOutputPathWithResultOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write result.json: %v", err)
	}
	got, err := nextAutoJSONOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result1.json")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestNextAutoJSONOutputPathWithResultOneUsesMaxPlusOne(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	seed := []string{"result.json", "result1.json", "result2.json", "result9.json"}
	for _, name := range seed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	got, err := nextAutoJSONOutputPath(dir)
	if err != nil {
		t.Fatalf("nextAutoJSONOutputPath returned error: %v", err)
	}
	want := filepath.Join(dir, "result10.json")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveOutputPathAutoSBOMSentinel(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir failed: %v", err)
	}
	defer func() {
		_ = os.Chdir(orig)
	}()

	resolved, autoGenerated, err := resolveOutputPath(autoSBOMOutputSentinel)
	if err != nil {
		t.Fatalf("resolveOutputPath returned error: %v", err)
	}
	if !autoGenerated {
		t.Fatal("expected autoGenerated=true for sbom sentinel")
	}
	want := filepath.Join(dir, "result.json")
	if resolved != want {
		t.Fatalf("expected %q, got %q", want, resolved)
	}
}

func TestResolveModuleWorkerLimitHonorsEnv(t *testing.T) {
	t.Setenv("C_EYES_MODULE_WORKERS", "3")
	if got := resolveModuleWorkerLimit(10); got != 3 {
		t.Fatalf("expected env worker limit 3, got %d", got)
	}
}

func TestResolveModuleWorkerLimitClampsToModuleCount(t *testing.T) {
	t.Setenv("C_EYES_MODULE_WORKERS", "8")
	if got := resolveModuleWorkerLimit(2); got != 2 {
		t.Fatalf("expected clamp to module count 2, got %d", got)
	}
}

func TestResolveModuleWorkerProfileForcedWorkersDisablesAdaptive(t *testing.T) {
	t.Setenv("C_EYES_MODULE_WORKERS", "3")
	profile := resolveModuleWorkerProfile(10)
	if profile.min != 3 || profile.initial != 3 || profile.max != 3 {
		t.Fatalf("unexpected fixed profile: %+v", profile)
	}
	if profile.adaptive {
		t.Fatal("expected adaptive=false when fixed workers are forced")
	}
}

func TestResolveModuleWorkerProfileDisableAdaptiveEnv(t *testing.T) {
	t.Setenv("C_EYES_MODULE_DISABLE_ADAPTIVE", "true")
	profile := resolveModuleWorkerProfile(6)
	if profile.adaptive {
		t.Fatal("expected adaptive disabled by env")
	}
	if profile.max < profile.initial || profile.initial < profile.min {
		t.Fatalf("invalid profile bounds: %+v", profile)
	}
}

func TestDecideNextModuleWorkerLimit(t *testing.T) {
	profile := moduleWorkerProfile{
		min:          1,
		max:          6,
		cpuHigh:      0.90,
		cpuLow:       0.60,
		memHighBytes: moduleMiBToBytes(2048),
		memLowBytes:  moduleMiBToBytes(512),
	}

	up := decideNextModuleWorkerLimit(2, 20, moduleRuntimeStats{
		cpuUtilization: 0.20,
		cpuValid:       true,
		memoryBytes:    moduleMiBToBytes(256),
	}, profile)
	if up != 3 {
		t.Fatalf("expected scale up to 3, got %d", up)
	}

	down := decideNextModuleWorkerLimit(4, 20, moduleRuntimeStats{
		cpuUtilization: 0.95,
		cpuValid:       true,
		memoryBytes:    moduleMiBToBytes(256),
	}, profile)
	if down != 3 {
		t.Fatalf("expected scale down to 3 on high cpu, got %d", down)
	}

	memDown := decideNextModuleWorkerLimit(3, 20, moduleRuntimeStats{
		cpuUtilization: 0.10,
		cpuValid:       true,
		memoryBytes:    moduleMiBToBytes(2500),
	}, profile)
	if memDown != 2 {
		t.Fatalf("expected scale down to 2 on high memory, got %d", memDown)
	}
}

func legacyAnySliceToMapRows(values any) ([]map[string]any, error) {
	rv := reflect.ValueOf(values)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil, nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return nil, nil
	}

	rows := make([]map[string]any, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		row, err := anyToMap(rv.Index(i).Interface())
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func collectHeadersLegacy(rows []map[string]any) []string {
	headerSet := make(map[string]struct{})
	for _, row := range rows {
		flat := flattenRow(row)
		for key := range flat {
			headerSet[key] = struct{}{}
		}
	}
	headers := make([]string, 0, len(headerSet))
	for key := range headerSet {
		headers = append(headers, key)
	}
	sort.Strings(headers)
	return headers
}

func runUnifiedCLIWithCapturedStderr(t *testing.T, args []string) (int, string) {
	t.Helper()

	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe error: %v", err)
	}
	os.Stderr = writer

	outputC := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		outputC <- string(data)
	}()

	code := runUnifiedCLI(args)
	_ = writer.Close()
	output := <-outputC
	_ = reader.Close()
	os.Stderr = originalStderr
	return code, output
}

func fileSizeOrZero(info os.FileInfo) int64 {
	if info == nil {
		return 0
	}
	return info.Size()
}
