package riskanalysis

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LocalMatcher evaluates scan targets using local matching.
type LocalMatcher interface {
	Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error)
}

// YaraXEngine defines the embedded YARA-X interface.
type YaraXEngine interface {
	MatchFile(ctx context.Context, path string) ([]YaraRuleMatch, error)
	MatchBytes(ctx context.Context, data []byte) ([]YaraRuleMatch, error)
}

// YaraXMatcher runs local YARA-X matches.
type YaraXMatcher struct {
	Engine          YaraXEngine
	CurrentHostname string
	CurrentPID      int
	CurrentExePath  string
}

// ConcurrentSafe indicates YaraXMatcher can be used by parallel analyzer workers.
func (m *YaraXMatcher) ConcurrentSafe() bool {
	return true
}

func (m *YaraXMatcher) Match(ctx context.Context, target TargetMetadata, record ScanRecord) (LocalAnalysis, float64, error) {
	if m == nil || m.Engine == nil {
		return LocalAnalysis{}, 0, fmt.Errorf("yara-x engine is not configured")
	}
	if m.isSelfExecutablePathTarget(target) {
		return LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: "skipped local matching for current c-eyes executable",
		}, 0, nil
	}
	if m.isSelfProcessTarget(target) {
		return LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: "skipped local matching for current c-eyes process",
		}, 0, nil
	}
	if strings.EqualFold(strings.TrimSpace(target.TargetType), TargetTypeProcessMemory) {
		return m.matchProcessMemory(ctx, record)
	}
	if target.TargetPath == "" {
		return LocalAnalysis{LocalMatched: false}, 0, nil
	}

	currentHost := m.currentHostname()
	sourceHost := strings.TrimSpace(target.SourceHostname)
	if sourceHost != "" {
		if currentHost != "" && !hostnamesEquivalent(sourceHost, currentHost) {
			return LocalAnalysis{
				LocalMatched:        false,
				LocalFallback:       true,
				LocalFallbackReason: fmt.Sprintf("source hostname %q differs from current hostname %q; skipped local matching to avoid cross-host path confusion", sourceHost, currentHost),
			}, 0, nil
		}
	}

	algo, expectedHash := expectedTargetHash(target.Hashes)
	if sourceHost == "" && expectedHash == "" {
		return LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: "missing source hostname and file hash; skipped local matching to avoid cross-host path confusion",
		}, 0, nil
	}
	if algo != "" && expectedHash != "" {
		actualHash, err := fileHash(target.TargetPath, algo)
		if err != nil {
			if isRecoverableLocalPathError(err) {
				return LocalAnalysis{
					LocalMatched:        false,
					LocalFallback:       true,
					LocalFallbackReason: fmt.Sprintf("cannot access target_path %q: %v", target.TargetPath, err),
				}, 0, nil
			}
			return LocalAnalysis{}, 0, err
		}
		if !strings.EqualFold(actualHash, expectedHash) {
			return LocalAnalysis{
				LocalMatched:        false,
				LocalFallback:       true,
				LocalFallbackReason: fmt.Sprintf("target_path %q hash mismatch (%s): expected %s, got %s; skipped local matching", target.TargetPath, algo, expectedHash, actualHash),
			}, 0, nil
		}
	}

	matches, err := m.Engine.MatchFile(ctx, target.TargetPath)
	if err != nil {
		if isRecoverableLocalPathError(err) {
			return LocalAnalysis{
				LocalMatched:        false,
				LocalFallback:       true,
				LocalFallbackReason: fmt.Sprintf("cannot access target_path %q: %v", target.TargetPath, err),
			}, 0, nil
		}
		return LocalAnalysis{}, 0, err
	}
	analysis := LocalAnalysis{
		LocalMatched: len(matches) > 0,
		YaraResults:  matches,
	}
	return analysis, LocalScoreFromMatches(matches), nil
}

func (m *YaraXMatcher) matchProcessMemory(ctx context.Context, record ScanRecord) (LocalAnalysis, float64, error) {
	payload, err := memoryPayload(record.Raw)
	if err != nil {
		return LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: fmt.Sprintf("process memory payload unavailable: %v", err),
		}, 0, nil
	}
	if len(payload) == 0 {
		return LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: "process memory payload is empty",
		}, 0, nil
	}

	matches, err := m.Engine.MatchBytes(ctx, payload)
	if err != nil {
		return LocalAnalysis{}, 0, err
	}

	analysis := LocalAnalysis{
		LocalMatched: len(matches) > 0,
		YaraResults:  matches,
	}
	return analysis, LocalScoreFromMatches(matches), nil
}

func memoryPayload(raw map[string]any) ([]byte, error) {
	if raw == nil {
		return nil, fmt.Errorf("record is empty")
	}
	if msg, ok := stringFrom(raw, "_memory_error"); ok {
		return nil, errors.New(msg)
	}

	value, ok := raw["_memory_bytes"]
	if !ok {
		return nil, fmt.Errorf("missing _memory_bytes")
	}

	switch v := value.(type) {
	case []byte:
		out := make([]byte, len(v))
		copy(out, v)
		return out, nil
	case string:
		encoded := strings.TrimSpace(v)
		if encoded == "" {
			return nil, fmt.Errorf("empty _memory_bytes string")
		}
		if data, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			return data, nil
		}
		if data, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
			return data, nil
		}
		return nil, fmt.Errorf("_memory_bytes is not valid base64")
	case []any:
		data := make([]byte, 0, len(v))
		for i, item := range v {
			num, ok := toInt(item)
			if !ok || num < 0 || num > 255 {
				return nil, fmt.Errorf("_memory_bytes[%d] is not a valid byte", i)
			}
			data = append(data, byte(num))
		}
		return data, nil
	default:
		return nil, fmt.Errorf("unsupported _memory_bytes type %T", value)
	}
}

func (m *YaraXMatcher) currentHostname() string {
	if m != nil {
		if host := strings.TrimSpace(m.CurrentHostname); host != "" {
			return host
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(host)
}

func (m *YaraXMatcher) currentPID() int {
	if m != nil && m.CurrentPID > 0 {
		return m.CurrentPID
	}
	return os.Getpid()
}

func (m *YaraXMatcher) currentExePath() string {
	if m != nil {
		if path := strings.TrimSpace(m.CurrentExePath); path != "" {
			return normalizeComparablePath(path)
		}
	}
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return normalizeComparablePath(path)
}

func (m *YaraXMatcher) isSelfProcessTarget(target TargetMetadata) bool {
	targetType := strings.ToLower(strings.TrimSpace(target.TargetType))
	if targetType != strings.ToLower(TargetTypeProcess) && targetType != strings.ToLower(TargetTypeProcessMemory) {
		return false
	}
	if target.PID != nil && m.currentPID() > 0 && *target.PID == m.currentPID() {
		return true
	}
	return m.isSelfExecutablePathTarget(target)
}

func (m *YaraXMatcher) isSelfExecutablePathTarget(target TargetMetadata) bool {
	if strings.TrimSpace(target.TargetPath) == "" {
		return false
	}
	selfPath := m.currentExePath()
	if selfPath == "" {
		return false
	}
	return pathsEquivalent(target.TargetPath, selfPath)
}

func pathsEquivalent(a, b string) bool {
	na := normalizeComparablePath(a)
	nb := normalizeComparablePath(b)
	if na == "" || nb == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

func normalizeComparablePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && strings.TrimSpace(resolved) != "" {
		path = resolved
	}
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
}

func hostnamesEquivalent(a, b string) bool {
	aNorm := strings.ToLower(strings.TrimSpace(a))
	bNorm := strings.ToLower(strings.TrimSpace(b))
	if aNorm == "" || bNorm == "" {
		return false
	}
	if aNorm == bNorm {
		return true
	}
	aShort := strings.SplitN(aNorm, ".", 2)[0]
	bShort := strings.SplitN(bNorm, ".", 2)[0]
	return aShort != "" && aShort == bShort
}

func expectedTargetHash(hashes Hashes) (string, string) {
	if val := strings.ToLower(strings.TrimSpace(hashes.Sha256)); val != "" {
		return "sha256", val
	}
	if val := strings.ToLower(strings.TrimSpace(hashes.Md5)); val != "" {
		return "md5", val
	}
	if val := strings.ToLower(strings.TrimSpace(hashes.Sha1)); val != "" {
		return "sha1", val
	}
	return "", ""
}

func fileHash(path string, algo string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	var hasher hash.Hash
	switch strings.ToLower(strings.TrimSpace(algo)) {
	case "sha256":
		hasher = sha256.New()
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algo)
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func isRecoverableLocalPathError(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) || os.IsPermission(err) {
		return true
	}
	var pathErr *fs.PathError
	return errors.As(err, &pathErr)
}
