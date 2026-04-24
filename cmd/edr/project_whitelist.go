package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"edrsystem/internal/riskanalysis"
)

const (
	projectWhitelistEnableEnv           = "C_EYES_ENABLE_PROJECT_WHITELIST"
	projectWhitelistRootEnv             = "C_EYES_PROJECT_WHITELIST_ROOT"
	projectWhitelistBaselineEnv         = "C_EYES_PROJECT_HASH_BASELINE"
	projectWhitelistRefreshEnv          = "C_EYES_PROJECT_HASH_BASELINE_REFRESH"
	defaultProjectBaselineRelPath       = ".c-eyes/project-hash-baseline.sha256"
	projectBaselineMaxFileSize    int64 = 8 * 1024 * 1024
)

type projectWhitelistSetup struct {
	Enabled      bool
	ProjectRoot  string
	BaselinePath string
	HashCount    int
	Created      bool
}

func applyProjectWhitelistPolicy(policy *riskanalysis.WhitelistPolicy) (projectWhitelistSetup, error) {
	setup := projectWhitelistSetup{}
	if policy == nil {
		return setup, nil
	}
	enabled, explicit := readOptionalBoolEnv(projectWhitelistEnableEnv, true)
	if !enabled {
		return setup, nil
	}
	setup.Enabled = true

	root := detectCurrentProjectRoot()
	if root == "" {
		setup.Enabled = false
		if explicit {
			return setup, fmt.Errorf("project whitelist enabled but project root was not detected")
		}
		return setup, nil
	}
	setup.ProjectRoot = root

	baselinePath := resolveProjectBaselinePath(root)
	refresh := readBoolEnv(projectWhitelistRefreshEnv, false)
	created, count, err := ensureProjectHashBaseline(root, baselinePath, refresh)
	if err != nil {
		return setup, err
	}
	setup.BaselinePath = baselinePath
	setup.HashCount = count
	setup.Created = created

	if !containsPath(policy.EnterpriseHashFiles, baselinePath) {
		policy.EnterpriseHashFiles = append(policy.EnterpriseHashFiles, baselinePath)
	}
	return setup, nil
}

func resolveProjectBaselinePath(projectRoot string) string {
	if custom := strings.TrimSpace(os.Getenv(projectWhitelistBaselineEnv)); custom != "" {
		return filepath.Clean(custom)
	}
	return filepath.Join(projectRoot, filepath.FromSlash(defaultProjectBaselineRelPath))
}

func ensureProjectHashBaseline(projectRoot, baselinePath string, refresh bool) (bool, int, error) {
	projectRoot = filepath.Clean(projectRoot)
	baselinePath = filepath.Clean(baselinePath)
	if !refresh {
		if info, err := os.Stat(baselinePath); err == nil && !info.IsDir() {
			count, err := countBaselineHashes(baselinePath)
			return false, count, err
		}
	}

	hashes, err := generateProjectBaselineHashes(projectRoot)
	if err != nil {
		return false, 0, err
	}
	if len(hashes) == 0 {
		return false, 0, fmt.Errorf("no baseline hashes generated from project root %s", projectRoot)
	}
	if err := os.MkdirAll(filepath.Dir(baselinePath), 0o755); err != nil {
		return false, 0, err
	}
	if err := writeBaselineHashFile(baselinePath, hashes); err != nil {
		return false, 0, err
	}
	return true, len(hashes), nil
}

func countBaselineHashes(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		token := strings.Fields(line)[0]
		if len(strings.TrimSpace(token)) == 64 {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func generateProjectBaselineHashes(projectRoot string) ([]string, error) {
	projectRoot = filepath.Clean(projectRoot)
	hashSet := make(map[string]struct{}, 4096)

	err := filepath.WalkDir(projectRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, err := filepath.Rel(projectRoot, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		parts := strings.Split(relSlash, "/")
		top := parts[0]

		if entry.IsDir() {
			if shouldSkipProjectBaselineDir(top, relSlash) {
				return filepath.SkipDir
			}
			return nil
		}
		if !shouldIncludeProjectBaselineFile(top, relSlash) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if info.Size() <= 0 || info.Size() > projectBaselineMaxFileSize {
			return nil
		}
		sum, err := sha256File(path)
		if err != nil {
			return nil
		}
		if sum != "" {
			hashSet[sum] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	hashes := make([]string, 0, len(hashSet))
	for h := range hashSet {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return hashes, nil
}

func shouldSkipProjectBaselineDir(top, rel string) bool {
	top = strings.ToLower(strings.TrimSpace(top))
	switch top {
	case ".git", ".tmp", "tmp", "downloads", "third_party", "node_modules", "vendor":
		return true
	}
	rel = strings.ToLower(strings.TrimSpace(rel))
	if strings.HasPrefix(rel, ".codex/") {
		return true
	}
	return false
}

func shouldIncludeProjectBaselineFile(top, rel string) bool {
	top = strings.ToLower(strings.TrimSpace(top))
	rel = strings.ToLower(strings.TrimSpace(rel))

	switch top {
	case "cmd", "internal", "rules", "scripts", "docs", "openspec":
		return true
	case "":
		return false
	}

	base := filepath.Base(rel)
	switch base {
	case "go.mod", "go.sum", "c-eyes-cloud.example.json", "c-eyes-cloud.json":
		return true
	case "c-eyes", "c-eyes.exe":
		return true
	}
	return false
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeBaselineHashFile(path string, hashes []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString("# c-eyes project hash baseline\n"); err != nil {
		return err
	}
	if _, err := file.WriteString("# format: sha256 per line\n"); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := file.WriteString(h + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func detectCurrentProjectRoot() string {
	if envRoot := strings.TrimSpace(os.Getenv(projectWhitelistRootEnv)); envRoot != "" {
		if info, err := os.Stat(envRoot); err == nil && info.IsDir() {
			return filepath.Clean(envRoot)
		}
	}

	candidates := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil && strings.TrimSpace(cwd) != "" {
		candidates = append(candidates, cwd)
	}
	if exe, err := os.Executable(); err == nil && strings.TrimSpace(exe) != "" {
		candidates = append(candidates, filepath.Dir(exe))
	}

	for _, start := range candidates {
		if root := findEDRProjectRoot(start); root != "" {
			return root
		}
	}
	return ""
}

func findEDRProjectRoot(start string) string {
	current := strings.TrimSpace(start)
	if current == "" {
		return ""
	}
	current = filepath.Clean(current)

	for depth := 0; depth < 12; depth++ {
		if isEDRProjectRoot(current) {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

func isEDRProjectRoot(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	goModPath := filepath.Join(dir, "go.mod")
	goMod, err := os.ReadFile(goModPath)
	if err != nil {
		return false
	}
	goModLower := strings.ToLower(string(goMod))
	if !strings.Contains(goModLower, "module edrsystem") {
		return false
	}

	cmdDir := filepath.Join(dir, "cmd", "edr")
	if info, err := os.Stat(cmdDir); err != nil || !info.IsDir() {
		return false
	}
	internalDir := filepath.Join(dir, "internal", "riskanalysis")
	if info, err := os.Stat(internalDir); err != nil || !info.IsDir() {
		return false
	}
	return true
}

func readBoolEnv(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func readOptionalBoolEnv(key string, defaultVal bool) (bool, bool) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return defaultVal, false
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return defaultVal, true
	}
}

func containsPath(paths []string, target string) bool {
	target = filepath.Clean(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, p := range paths {
		if filepath.Clean(strings.TrimSpace(p)) == target {
			return true
		}
	}
	return false
}
