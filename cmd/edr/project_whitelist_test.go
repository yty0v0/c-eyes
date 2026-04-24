package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"edrsystem/internal/riskanalysis"
)

func TestApplyProjectWhitelistPolicy_ExplicitDisable(t *testing.T) {
	root := makeTempProjectRoot(t)
	baselinePath := filepath.Join(root, ".c-eyes", "baseline.sha256")

	t.Setenv(projectWhitelistEnableEnv, "0")
	t.Setenv(projectWhitelistRootEnv, root)
	t.Setenv(projectWhitelistBaselineEnv, baselinePath)
	t.Setenv(projectWhitelistRefreshEnv, "1")

	policy := riskanalysis.WhitelistPolicy{Version: "1"}
	setup, err := applyProjectWhitelistPolicy(&policy)
	if err != nil {
		t.Fatalf("applyProjectWhitelistPolicy error: %v", err)
	}
	if setup.Enabled {
		t.Fatalf("expected project whitelist disabled when %s=0", projectWhitelistEnableEnv)
	}
	if setup.Created {
		t.Fatalf("expected no baseline creation when project whitelist is disabled")
	}
	if len(policy.EnterpriseHashFiles) != 0 {
		t.Fatalf("expected no enterprise hash files when disabled")
	}
	if _, err := os.Stat(baselinePath); !os.IsNotExist(err) {
		t.Fatalf("expected no baseline file when disabled, stat err=%v", err)
	}
}

func TestApplyProjectWhitelistPolicy_DefaultEnabledAndCreateBaseline(t *testing.T) {
	root := makeTempProjectRoot(t)
	baselinePath := filepath.Join(root, ".c-eyes", "baseline.sha256")

	t.Setenv(projectWhitelistEnableEnv, "")
	t.Setenv(projectWhitelistRootEnv, root)
	t.Setenv(projectWhitelistBaselineEnv, baselinePath)
	t.Setenv(projectWhitelistRefreshEnv, "1")

	policy := riskanalysis.WhitelistPolicy{Version: "1"}
	setup, err := applyProjectWhitelistPolicy(&policy)
	if err != nil {
		t.Fatalf("applyProjectWhitelistPolicy error: %v", err)
	}
	if !setup.Enabled {
		t.Fatalf("expected project whitelist enabled")
	}
	if !setup.Created {
		t.Fatalf("expected baseline to be created")
	}
	if setup.HashCount <= 0 {
		t.Fatalf("expected positive hash count, got %d", setup.HashCount)
	}
	if !containsPath(policy.EnterpriseHashFiles, baselinePath) {
		t.Fatalf("expected enterprise hash files to include %s", baselinePath)
	}
	content, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline file: %v", err)
	}
	if !strings.Contains(string(content), "# c-eyes project hash baseline") {
		t.Fatalf("expected baseline header in file")
	}
}

func TestApplyProjectWhitelistPolicy_DeduplicateBaselinePath(t *testing.T) {
	root := makeTempProjectRoot(t)
	baselinePath := filepath.Join(root, ".c-eyes", "baseline.sha256")
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		t.Fatalf("mkdir baseline dir: %v", err)
	}
	if err := os.WriteFile(baselinePath, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	t.Setenv(projectWhitelistEnableEnv, "1")
	t.Setenv(projectWhitelistRootEnv, root)
	t.Setenv(projectWhitelistBaselineEnv, baselinePath)
	t.Setenv(projectWhitelistRefreshEnv, "0")

	policy := riskanalysis.WhitelistPolicy{
		Version:             "1",
		EnterpriseHashFiles: []string{baselinePath},
	}
	setup, err := applyProjectWhitelistPolicy(&policy)
	if err != nil {
		t.Fatalf("applyProjectWhitelistPolicy error: %v", err)
	}
	if !setup.Enabled {
		t.Fatalf("expected project whitelist enabled")
	}
	if len(policy.EnterpriseHashFiles) != 1 {
		t.Fatalf("expected deduplicated baseline path, got %d items", len(policy.EnterpriseHashFiles))
	}
}

func TestFindEDRProjectRoot(t *testing.T) {
	t.Parallel()

	root := makeTempProjectRoot(t)
	start := filepath.Join(root, "cmd", "edr", "nested")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatalf("mkdir start: %v", err)
	}

	got := findEDRProjectRoot(start)
	if filepath.Clean(got) != filepath.Clean(root) {
		t.Fatalf("expected project root %q, got %q", root, got)
	}
}

func makeTempProjectRoot(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module edrsystem\n\ngo 1.25.0\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "cmd", "edr"), 0o755); err != nil {
		t.Fatalf("mkdir cmd/edr: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "internal", "riskanalysis"), 0o755); err != nil {
		t.Fatalf("mkdir internal/riskanalysis: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "cmd", "edr", "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatalf("write cmd file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "riskanalysis", "types.go"), []byte("package riskanalysis\n"), 0o600); err != nil {
		t.Fatalf("write internal file: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "third_party"), 0o755); err != nil {
		t.Fatalf("mkdir third_party: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "third_party", "large.bin"), make([]byte, 1024), 0o600); err != nil {
		t.Fatalf("write third_party file: %v", err)
	}
	return root
}
