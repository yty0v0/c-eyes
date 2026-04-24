package riskanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateYaraRulesPath_DirectoryRequiresRuleFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a rule"), 0o600); err != nil {
		t.Fatalf("write marker file: %v", err)
	}

	err := validateYaraRulesPath(dir)
	if err == nil {
		t.Fatal("expected validation error for directory without rule files")
	}
}

func TestValidateYaraRulesPath_DirectoryWithRuleFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.yar"), []byte("rule test { condition: true }"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	if err := validateYaraRulesPath(dir); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestNoopYaraXEngine_MatchFileReturnsNoMatches(t *testing.T) {
	t.Parallel()

	engine := &noopYaraXEngine{warning: "degraded"}
	matches, err := engine.MatchFile(context.Background(), "ignored")
	if err != nil {
		t.Fatalf("unexpected match error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
	if got := YaraXEngineWarning(engine); got != "degraded" {
		t.Fatalf("unexpected warning text: %q", got)
	}
}

func TestNoopYaraXEngine_MatchBytesReturnsNoMatches(t *testing.T) {
	t.Parallel()

	engine := &noopYaraXEngine{warning: "degraded"}
	matches, err := engine.MatchBytes(context.Background(), []byte("test"))
	if err != nil {
		t.Fatalf("unexpected match error: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(matches))
	}
}
