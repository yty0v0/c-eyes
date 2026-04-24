package filescan

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
)

const defaultRuleMaxBytes = 2 << 20

type ruleSet struct {
	hashes   map[string]struct{}
	patterns []string
	maxBytes int
}

var (
	rulesOnce sync.Once
	rulesData ruleSet
)

// RuleDeepScanner matches files against simple hash and string rules.
type RuleDeepScanner struct{}

func (RuleDeepScanner) Scan(ctx context.Context, task ScanTask) (DeepScanResult, error) {
	_ = ctx
	rules := loadRules()
	if len(rules.hashes) == 0 && len(rules.patterns) == 0 {
		return DeepScanResult{Result: ScanResultUnknown}, nil
	}

	hashes, err := fileHashes(task.Path)
	if err != nil && isPermissionDeniedError(err) {
		return DeepScanResult{}, err
	}
	if err == nil && hashes != nil {
		if hashes.Sha256 != nil {
			if _, ok := rules.hashes[strings.ToLower(*hashes.Sha256)]; ok {
				return DeepScanResult{Result: ScanResultMalicious}, nil
			}
		}
	}

	if len(rules.patterns) == 0 {
		return DeepScanResult{Result: ScanResultUnknown}, nil
	}

	content, err := readFilePrefix(task.Path, rules.maxBytes)
	if err != nil {
		if isPermissionDeniedError(err) {
			return DeepScanResult{}, err
		}
		return DeepScanResult{Result: ScanResultUnknown}, nil
	}
	lower := strings.ToLower(content)
	for _, pattern := range rules.patterns {
		if pattern == "" {
			continue
		}
		if strings.Contains(lower, pattern) {
			return DeepScanResult{Result: ScanResultMalicious}, nil
		}
	}

	return DeepScanResult{Result: ScanResultUnknown}, nil
}

func loadRules() ruleSet {
	rulesOnce.Do(func() {
		rulesData.maxBytes = defaultRuleMaxBytes
		hashPath := os.Getenv("C_EYES_FILE_HASH_BLACKLIST")
		patternPath := os.Getenv("C_EYES_FILE_STRING_RULES")

		if hashPath != "" {
			rulesData.hashes = readRuleSet(hashPath)
		} else {
			rulesData.hashes = make(map[string]struct{})
		}
		if patternPath != "" {
			rulesData.patterns = readRuleList(patternPath)
		}
	})
	return rulesData
}

func readRuleSet(path string) map[string]struct{} {
	file, err := os.Open(path)
	if err != nil {
		return make(map[string]struct{})
	}
	defer file.Close()

	set := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	return set
}

func readRuleList(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, strings.ToLower(line))
	}
	return patterns
}

func readFilePrefix(path string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = defaultRuleMaxBytes
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := make([]byte, maxBytes)
	n, err := file.Read(buf)
	if n > 0 {
		return string(buf[:n]), nil
	}
	return "", err
}
