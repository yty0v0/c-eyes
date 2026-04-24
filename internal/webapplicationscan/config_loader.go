package webapplicationscan

import (
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reNginxInclude  = regexp.MustCompile(`(?mi)^\s*include\s+([^;#\r\n]+)\s*;`)
	reApacheInclude = regexp.MustCompile(`(?mi)^\s*Include(?:Optional)?\s+([^\r\n#]+)`)
)

func loadConfigWithIncludes(path string, readFile func(string) ([]byte, error)) (string, string, error) {
	real := resolveSymlinkPath(path)
	visited := map[string]struct{}{}
	merged, err := loadConfigRecursive(real, readFile, 0, 4, visited)
	return real, merged, err
}

func loadConfigRecursive(path string, readFile func(string) ([]byte, error), depth, maxDepth int, visited map[string]struct{}) (string, error) {
	if depth > maxDepth {
		return "", nil
	}
	real := resolveSymlinkPath(path)
	key := strings.ToLower(filepath.Clean(real))
	if _, ok := visited[key]; ok {
		return "", nil
	}
	visited[key] = struct{}{}

	data, err := readFile(real)
	if err != nil {
		return "", err
	}
	content := string(data)
	builder := strings.Builder{}
	builder.WriteString(content)
	builder.WriteString("\n")

	for _, includePath := range discoverIncludeCandidates(real, content) {
		child, err := loadConfigRecursive(includePath, readFile, depth+1, maxDepth, visited)
		if err != nil || strings.TrimSpace(child) == "" {
			continue
		}
		builder.WriteString("\n")
		builder.WriteString(child)
	}
	return builder.String(), nil
}

func discoverIncludeCandidates(basePath, content string) []string {
	out := make([]string, 0, 8)
	baseDir := filepath.Dir(basePath)

	for _, m := range reNginxInclude.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		out = append(out, expandIncludePattern(baseDir, cleanIncludeToken(m[1]))...)
	}
	for _, m := range reApacheInclude.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		out = append(out, expandIncludePattern(baseDir, cleanIncludeToken(m[1]))...)
	}
	return uniquePaths(out)
}

func expandIncludePattern(baseDir, pattern string) []string {
	if pattern == "" {
		return nil
	}
	candidate := pattern
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(baseDir, candidate)
	}
	candidate = resolveSymlinkPath(candidate)
	if strings.Contains(candidate, "*") || strings.Contains(candidate, "?") {
		matches, err := filepath.Glob(candidate)
		if err != nil {
			return nil
		}
		return matches
	}
	return []string{candidate}
}

func cleanIncludeToken(v string) string {
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func uniquePaths(list []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(list))
	for _, item := range list {
		key := strings.ToLower(filepath.Clean(item))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func resolveSymlinkPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return path
	}
	resolved, err := filepath.EvalSymlinks(trimmed)
	if err != nil || strings.TrimSpace(resolved) == "" {
		return filepath.Clean(trimmed)
	}
	return filepath.Clean(resolved)
}
