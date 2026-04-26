package riskanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

type stubYaraXEngine struct {
	matches     []YaraRuleMatch
	err         error
	calls       *int
	byteCalls   *int
	bytesErr    error
	bytesResult []YaraRuleMatch
}

func (s stubYaraXEngine) MatchFile(ctx context.Context, path string) ([]YaraRuleMatch, error) {
	if s.calls != nil {
		*s.calls = *s.calls + 1
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.matches, nil
}

func (s stubYaraXEngine) MatchBytes(ctx context.Context, data []byte) ([]YaraRuleMatch, error) {
	if s.byteCalls != nil {
		*s.byteCalls = *s.byteCalls + 1
	}
	if s.bytesErr != nil {
		return nil, s.bytesErr
	}
	return s.bytesResult, nil
}

func TestYaraXMatcherFallbackOnMissingFile(t *testing.T) {
	t.Parallel()

	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{
			err: &fs.PathError{
				Op:   "open",
				Path: "Z:/remote-host/sample.exe",
				Err:  fs.ErrNotExist,
			},
		},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath: "Z:/remote-host/sample.exe",
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if analysis.LocalMatched {
		t.Fatal("expected local_matched=false for fallback")
	}
	if !analysis.LocalFallback {
		t.Fatal("expected local_fallback=true")
	}
	if analysis.LocalFallbackReason == "" {
		t.Fatal("expected non-empty fallback reason")
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherFallbackOnSourceHostMismatch(t *testing.T) {
	t.Parallel()

	calls := 0
	matcher := &YaraXMatcher{
		Engine:          stubYaraXEngine{calls: &calls},
		CurrentHostname: "local-host",
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath:     "C:/Windows/System32/notepad.exe",
		SourceHostname: "remote-host",
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected local fallback for host mismatch")
	}
	if calls != 0 {
		t.Fatalf("expected engine not called, got %d calls", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherFallbackOnHashMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	calls := 0
	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{calls: &calls},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath: path,
		Hashes: Hashes{
			Sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		},
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected local fallback for hash mismatch")
	}
	if calls != 0 {
		t.Fatalf("expected engine not called, got %d calls", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherFallbackWithoutHostAndHash(t *testing.T) {
	t.Parallel()

	calls := 0
	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{calls: &calls},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath: "C:/Windows/System32/notepad.exe",
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected fallback when host/hash identity is missing")
	}
	if calls != 0 {
		t.Fatalf("expected engine not called, got %d calls", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherRunsOnHashMatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	content := []byte("hello")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])

	calls := 0
	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{
			calls:   &calls,
			matches: []YaraRuleMatch{{RuleName: "r1", Severity: 80}},
		},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath: path,
		Hashes: Hashes{
			Sha256: expected,
		},
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if analysis.LocalFallback {
		t.Fatal("did not expect fallback for hash match")
	}
	if !analysis.LocalMatched {
		t.Fatal("expected local_matched=true")
	}
	if calls != 1 {
		t.Fatalf("expected engine called once, got %d calls", calls)
	}
	if score <= 0 {
		t.Fatalf("expected positive score, got %v", score)
	}
}

func TestYaraXMatcherReturnsErrorForEngineFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "sample.bin")
	content := []byte("hello")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	sum := sha256.Sum256(content)
	expected := hex.EncodeToString(sum[:])

	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{
			err: errors.New("scanner init failed"),
		},
	}

	_, _, err := matcher.Match(context.Background(), TargetMetadata{
		TargetPath: path,
		Hashes: Hashes{
			Sha256: expected,
		},
	}, ScanRecord{})
	if err == nil {
		t.Fatal("expected fatal engine error")
	}
}

func TestYaraXMatcherProcessMemoryUsesBytes(t *testing.T) {
	t.Parallel()

	fileCalls := 0
	byteCalls := 0
	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{
			calls:       &fileCalls,
			byteCalls:   &byteCalls,
			bytesResult: []YaraRuleMatch{{RuleName: "mem_rule", Severity: 95}},
		},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetType: TargetTypeProcessMemory,
	}, ScanRecord{
		Raw: map[string]any{
			"_memory_bytes": []byte{0x41, 0x42, 0x43},
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if analysis.LocalFallback {
		t.Fatal("did not expect fallback")
	}
	if !analysis.LocalMatched {
		t.Fatal("expected local_matched=true")
	}
	if fileCalls != 0 {
		t.Fatalf("expected MatchFile not called, got %d", fileCalls)
	}
	if byteCalls != 1 {
		t.Fatalf("expected MatchBytes called once, got %d", byteCalls)
	}
	if score <= 0 {
		t.Fatalf("expected positive score, got %v", score)
	}
}

func TestYaraXMatcherProcessMemoryFallbackWhenPayloadMissing(t *testing.T) {
	t.Parallel()

	byteCalls := 0
	matcher := &YaraXMatcher{
		Engine: stubYaraXEngine{
			byteCalls: &byteCalls,
		},
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetType: TargetTypeProcessMemory,
	}, ScanRecord{
		Raw: map[string]any{},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected local_fallback=true")
	}
	if analysis.LocalFallbackReason == "" {
		t.Fatal("expected non-empty fallback reason")
	}
	if byteCalls != 0 {
		t.Fatalf("expected MatchBytes not called, got %d", byteCalls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherSkipsSelfProcessByPID(t *testing.T) {
	t.Parallel()

	calls := 0
	matcher := &YaraXMatcher{
		Engine:     stubYaraXEngine{calls: &calls},
		CurrentPID: 4242,
	}
	pid := 4242

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetType: TargetTypeProcess,
		TargetPath: `C:\tools\c-eyes.exe`,
		PID:        &pid,
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected fallback for self process")
	}
	if analysis.LocalMatched {
		t.Fatal("expected local_matched=false for self process")
	}
	if calls != 0 {
		t.Fatalf("expected MatchFile not called, got %d", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherSkipsSelfProcessByPath(t *testing.T) {
	t.Parallel()

	calls := 0
	matcher := &YaraXMatcher{
		Engine:         stubYaraXEngine{calls: &calls},
		CurrentExePath: `C:\TOOLS\c-eyes.exe`,
		CurrentPID:     9999,
	}
	pid := 1234

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetType: TargetTypeProcess,
		TargetPath: `c:\tools\c-eyes.exe`,
		PID:        &pid,
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected fallback for self process path")
	}
	if analysis.LocalMatched {
		t.Fatal("expected local_matched=false for self process path")
	}
	if calls != 0 {
		t.Fatalf("expected MatchFile not called, got %d", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}

func TestYaraXMatcherSkipsSelfFileByPath(t *testing.T) {
	t.Parallel()

	calls := 0
	matcher := &YaraXMatcher{
		Engine:         stubYaraXEngine{calls: &calls},
		CurrentExePath: `/home/kali/Desktop/dist-linux-amd64/c-eyes`,
	}

	analysis, score, err := matcher.Match(context.Background(), TargetMetadata{
		TargetType: TargetTypeFile,
		TargetPath: `/home/kali/Desktop/dist-linux-amd64/c-eyes`,
	}, ScanRecord{})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !analysis.LocalFallback {
		t.Fatal("expected fallback for self executable file path")
	}
	if analysis.LocalMatched {
		t.Fatal("expected local_matched=false for self executable file path")
	}
	if calls != 0 {
		t.Fatalf("expected MatchFile not called, got %d", calls)
	}
	if score != 0 {
		t.Fatalf("expected score=0, got %v", score)
	}
}
