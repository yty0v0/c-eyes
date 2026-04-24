package riskanalysis

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AuthorityHashRepo resolves trusted hashes from authority sources.
type AuthorityHashRepo interface {
	Lookup(sha256 string) (source string, ok bool)
}

type staticAuthorityHashRepo struct {
	index map[string]string
}

func (r *staticAuthorityHashRepo) Lookup(sha256 string) (string, bool) {
	if r == nil || len(r.index) == 0 {
		return "", false
	}
	key := normalizeHex(sha256)
	if key == "" {
		return "", false
	}
	source, ok := r.index[key]
	return source, ok
}

// NewAuthorityHashRepo builds hash repository adapters for NSRL and enterprise baseline data.
func NewAuthorityHashRepo(policy *WhitelistPolicy) (AuthorityHashRepo, error) {
	index := make(map[string]string)
	if policy == nil {
		return &staticAuthorityHashRepo{index: index}, nil
	}

	for _, h := range policy.NSRLHashes {
		if key := normalizeHex(h); key != "" {
			index[key] = "nsrl"
		}
	}
	for _, h := range policy.EnterpriseHashes {
		if key := normalizeHex(h); key != "" {
			index[key] = "enterprise_baseline"
		}
	}

	if err := loadHashFiles(index, policy.NSRLHashFiles, "nsrl"); err != nil {
		return nil, err
	}
	if err := loadHashFiles(index, policy.EnterpriseHashFiles, "enterprise_baseline"); err != nil {
		return nil, err
	}
	return &staticAuthorityHashRepo{index: index}, nil
}

func loadHashFiles(index map[string]string, paths []string, source string) error {
	for _, p := range paths {
		path := strings.TrimSpace(p)
		if path == "" {
			continue
		}
		if err := loadHashFile(index, path, source); err != nil {
			return err
		}
	}
	return nil
}

func loadHashFile(index map[string]string, path, source string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("hash file open failed (%s): %w", path, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Support CSV and text modes: take first token/column as hash.
		token := line
		if strings.Contains(line, ",") {
			token = strings.Split(line, ",")[0]
		} else if strings.Contains(line, "\t") {
			token = strings.Split(line, "\t")[0]
		} else {
			token = strings.Fields(line)[0]
		}
		key := normalizeHex(token)
		if key == "" {
			continue
		}
		if len(key) != 64 {
			// Ignore non-sha256 rows instead of failing whole import.
			continue
		}
		index[key] = source
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("hash file parse failed (%s): %w", filepath.Clean(path), err)
	}
	return nil
}
