package main

import (
	"strings"
	"testing"

	"edrsystem/internal/riskanalysis"
)

func TestParseRiskFlagsInputSource(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-input", "scan.json", "-risk-mode", "local_only"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.InputPath != "scan.json" {
		t.Fatalf("expected input path scan.json, got %q", opts.InputPath)
	}
	if opts.Mode != "local_only" {
		t.Fatalf("expected risk-mode=local_only, got %q", opts.Mode)
	}
}

func TestParseRiskFlagsModeAlias(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-input", "scan.json", "-mode", "smart"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.Mode != "smart" {
		t.Fatalf("expected mode alias to map to smart, got %q", opts.Mode)
	}
}

func TestParseRiskFlagsFileSource(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-file", "C:/tmp/sample.bin"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.FilePath != "C:/tmp/sample.bin" {
		t.Fatalf("expected file path, got %q", opts.FilePath)
	}
}

func TestParseRiskFlagsDirSource(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-dir", "C:/tmp"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.DirPath != "C:/tmp" {
		t.Fatalf("expected dir path, got %q", opts.DirPath)
	}
}

func TestParseRiskFlagsMutuallyExclusiveSources(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-file", "C:/tmp/sample.bin"})
	if err == nil {
		t.Fatal("expected mutually exclusive source error")
	}
	if !strings.Contains(err.Error(), "analysis source parameters are mutually exclusive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsProcessByPID(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-pid", "1234"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.ProcessPID != 1234 {
		t.Fatalf("expected pid=1234, got %d", opts.ProcessPID)
	}
}

func TestParseRiskFlagsProcessByName(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-pname", "chrome"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if opts.ProcessName != "chrome" {
		t.Fatalf("expected pname=chrome, got %q", opts.ProcessName)
	}
}

func TestParseRiskFlagsInvalidPID(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-pid", "0"})
	if err == nil {
		t.Fatal("expected invalid pid error")
	}
	if !strings.Contains(err.Error(), "-pid must be greater than 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsProcessMemoryRequiresProcessSource(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-process-memory"})
	if err == nil {
		t.Fatal("expected process-memory validation error")
	}
	if !strings.Contains(err.Error(), "-process-memory is only supported with -pid/-pname") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsProcessMemoryByPIDUsesDefaultLimit(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{"-pid", "1234", "-process-memory"})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if !opts.ProcessMemory {
		t.Fatal("expected process-memory=true")
	}
	if opts.MemoryMaxBytes != riskanalysis.DefaultProcessMemoryMaxBytes {
		t.Fatalf("expected default memory-max-bytes=%d, got %d", riskanalysis.DefaultProcessMemoryMaxBytes, opts.MemoryMaxBytes)
	}
}

func TestParseRiskFlagsRejectsRemovedAdvancedFlags(t *testing.T) {
	t.Parallel()

	cases := []string{
		"-memory-max-bytes",
		"-yara-read-chunk",
		"-local-weight",
		"-cloud-weight",
		"-cloud-upload-concurrency",
		"-cloud-upload-wait",
		"-cloud-upload-submit-timeout",
		"-cloud-upload-poll-interval",
		"-cloud-upload-max-size",
		"-excel",
		"-json",
	}

	for _, flagName := range cases {
		flagName := flagName
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()

			_, err := parseRiskFlags([]string{"-input", "scan.json", flagName, "1"})
			if err == nil {
				t.Fatalf("expected %s parse error", flagName)
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseRiskFlagsRejectsLegacyLocalFlag(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-local"})
	if err == nil {
		t.Fatal("expected legacy -local flag parse error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined: -local") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsRejectsLegacyCloudProviderFlag(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-cloud-provider", "triage"})
	if err == nil {
		t.Fatal("expected legacy -cloud-provider flag parse error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined: -cloud-provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsRejectsLegacyCloudFlag(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-cloud"})
	if err == nil {
		t.Fatal("expected legacy -cloud flag parse error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined: -cloud") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseRiskFlagsRejectsLegacyRecursiveFlag(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-dir", "C:/tmp", "-r"})
	if err == nil {
		t.Fatal("expected legacy -r flag parse error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined: -r") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRiskModeDefaultsToSmart(t *testing.T) {
	t.Parallel()

	mode, err := resolveRiskMode("")
	if err != nil {
		t.Fatalf("resolveRiskMode returned error: %v", err)
	}
	if mode != "smart" {
		t.Fatalf("expected default mode smart, got %s", mode)
	}
}

func TestResolveRiskModeHybridAlias(t *testing.T) {
	t.Parallel()

	mode, err := resolveRiskMode("hybrid")
	if err != nil {
		t.Fatalf("resolveRiskMode returned error: %v", err)
	}
	if mode != "smart" {
		t.Fatalf("expected hybrid alias to resolve smart, got %s", mode)
	}
}

func TestParseRiskFlagsCloudUploadOptions(t *testing.T) {
	t.Parallel()

	opts, err := parseRiskFlags([]string{
		"-input", "scan.json",
		"-cloud-upload",
		"-analysis-max-duration", "10m",
	})
	if err != nil {
		t.Fatalf("parseRiskFlags returned error: %v", err)
	}
	if !opts.CloudUpload {
		t.Fatal("expected cloud-upload=true")
	}
	if opts.AnalysisMaxDuration.String() != "10m0s" {
		t.Fatalf("expected analysis-max-duration=10m, got %s", opts.AnalysisMaxDuration)
	}
}

func TestParseRiskFlagsInvalidAnalysisMaxDuration(t *testing.T) {
	t.Parallel()

	_, err := parseRiskFlags([]string{"-input", "scan.json", "-analysis-max-duration", "-1s"})
	if err == nil {
		t.Fatal("expected analysis-max-duration validation error")
	}
	if !strings.Contains(err.Error(), "-analysis-max-duration must be greater than or equal to 0") {
		t.Fatalf("unexpected error: %v", err)
	}
}
