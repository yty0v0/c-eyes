package filescan

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	smartBudgetMin = 300
	smartBudgetMax = 30000
)

type smartRankedTask struct {
	task  ScanTask
	score int
	index int
}

// selectSmartSubset keeps only high-risk/sensitive targets from declared scope.
func selectSmartSubset(tasks []ScanTask, params FileScanParams) []ScanTask {
	if len(tasks) == 0 {
		return nil
	}
	candidates := make([]ScanTask, len(tasks))
	copy(candidates, tasks)

	if params.Mode == ScanModePath {
		candidates = filterTasksWithinScope(candidates, params.Path)
	}
	if len(candidates) == 0 {
		return nil
	}

	budget := smartSubsetBudget(len(candidates), params.MaxTargets)
	if budget <= 0 {
		return nil
	}
	if budget >= len(candidates) {
		return candidates
	}

	now := time.Now()
	ranked := make([]smartRankedTask, 0, len(candidates))
	for idx, task := range candidates {
		ranked = append(ranked, smartRankedTask{
			task:  task,
			score: smartSubsetScore(task.Path, now),
			index: idx,
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score == ranked[j].score {
			return ranked[i].index < ranked[j].index
		}
		return ranked[i].score > ranked[j].score
	})

	selected := make([]ScanTask, 0, budget)
	for i := 0; i < budget && i < len(ranked); i++ {
		selected = append(selected, ranked[i].task)
	}
	return selected
}

func smartSubsetBudget(total, maxTargets int) int {
	if total <= 0 {
		return 0
	}
	var raw float64
	switch {
	case total <= 5000:
		raw = float64(total) * 0.35
	case total <= 50000:
		raw = float64(total) * 0.15
	default:
		raw = float64(total) * 0.08
	}
	budget := int(math.Ceil(raw))
	if budget < smartBudgetMin {
		budget = smartBudgetMin
	}
	if budget > smartBudgetMax {
		budget = smartBudgetMax
	}
	if budget > total {
		budget = total
	}
	if maxTargets > 0 && budget > maxTargets {
		budget = maxTargets
	}
	if budget < 1 {
		budget = 1
	}
	return budget
}

func smartSubsetScore(path string, now time.Time) int {
	score := 0
	lower := strings.ToLower(path)

	for _, token := range []string{
		"downloads",
		"temp",
		"tmp",
		"appdata",
		"startup",
		"recycle",
		"$recycle.bin",
		".cache",
		".config/autostart",
	} {
		if strings.Contains(lower, token) {
			score += 40
			break
		}
	}

	switch strings.ToLower(filepath.Ext(lower)) {
	case ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".jar", ".sh", ".py", ".pl", ".so", ".dylib", ".elf":
		score += 35
	case ".zip", ".rar", ".7z", ".gz", ".tar":
		score += 20
	}

	for _, token := range []string{"autorun", "runonce", "services", "powershell", "wscript", "cscript"} {
		if strings.Contains(lower, token) {
			score += 20
			break
		}
	}

	if info, err := os.Stat(path); err == nil {
		age := now.Sub(info.ModTime())
		switch {
		case age <= 72*time.Hour:
			score += 20
		case age <= 7*24*time.Hour:
			score += 10
		}
	}

	if score == 0 {
		return 1
	}
	return score
}

func filterTasksWithinScope(tasks []ScanTask, scope string) []ScanTask {
	scopePath := normalizeComparePath(scope)
	if scopePath == "" {
		return nil
	}
	filtered := make([]ScanTask, 0, len(tasks))
	for _, task := range tasks {
		if isPathWithinScope(task.Path, scopePath) {
			filtered = append(filtered, task)
		}
	}
	return filtered
}

func isPathWithinScope(path, scopePath string) bool {
	target := normalizeComparePath(path)
	if target == "" || scopePath == "" {
		return false
	}
	if hasScopePrefix(target, scopePath, string(filepath.Separator)) {
		return true
	}
	if runtime.GOOS == "windows" {
		targetAlt := strings.ReplaceAll(target, "\\", "/")
		scopeAlt := strings.ReplaceAll(scopePath, "\\", "/")
		if hasScopePrefix(targetAlt, scopeAlt, "/") {
			return true
		}
	}
	return false
}

func hasScopePrefix(target, scopePath, sep string) bool {
	if target == scopePath {
		return true
	}
	if strings.HasSuffix(scopePath, sep) {
		return strings.HasPrefix(target, scopePath)
	}
	return strings.HasPrefix(target, scopePath+sep)
}

func normalizeComparePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	cleaned := filepath.Clean(trimmed)
	if runtime.GOOS == "windows" {
		cleaned = strings.ToLower(cleaned)
	}
	return cleaned
}
