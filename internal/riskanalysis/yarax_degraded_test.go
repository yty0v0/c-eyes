//go:build !yarax || (yarax && !cgo)

package riskanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNewYaraXEngine_DegradedBuildStillInitializes(t *testing.T) {
	t.Parallel()

	rulesDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(rulesDir, "test_rule.yar"), []byte("rule test_rule { condition: true }"), 0o600); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	engine, err := NewYaraXEngine(YaraXConfig{RulesPath: rulesDir})
	if err != nil {
		t.Fatalf("expected degraded engine to initialize, got error: %v", err)
	}
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	warning := YaraXEngineWarning(engine)
	if warning == "" {
		t.Fatal("expected non-empty degraded warning")
	}

	sample := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(sample, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write sample file: %v", err)
	}

	matcher := &YaraXMatcher{Engine: engine}
	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{TargetPath: sample}, ScanRecord{})
	if err != nil {
		t.Fatalf("unexpected local match error: %v", err)
	}
	if analysis.LocalMatched {
		t.Fatal("expected degraded matcher to report no local match")
	}
	if len(analysis.YaraResults) != 0 {
		t.Fatalf("expected no yara results, got %d", len(analysis.YaraResults))
	}
	if score != 0 {
		t.Fatalf("expected score 0, got %v", score)
	}
}
