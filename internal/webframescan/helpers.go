package webframescan

import (
	"path/filepath"
	"sort"
	"strings"

	"edrsystem/internal/filterutil"
)

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func stringContainsAnyFold(value string, needles []string) bool {
	return filterutil.ContainsAnyFold(value, needles)
}

func nullableString(v string) *string {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil
	}
	return strPtr(trimmed)
}

func cloneStringPtr(v *string) *string {
	if v == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*v)
	if trimmed == "" {
		return nil
	}
	return strPtr(trimmed)
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func mergeStringSlices(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	appendAll := func(list []string) {
		for _, item := range list {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			key := strings.ToLower(trimmed)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, trimmed)
		}
	}
	appendAll(a)
	appendAll(b)
	sort.Strings(out)
	return out
}

func firstNonNil(a, b *string) *string {
	if clone := cloneStringPtr(a); clone != nil {
		return clone
	}
	return cloneStringPtr(b)
}

func deriveWorkDir(webRoot, webAppDir *string) *string {
	if out := cloneStringPtr(webRoot); out != nil {
		return out
	}
	if out := cloneStringPtr(webAppDir); out != nil {
		dir := filepath.Dir(*out)
		if dir == "." {
			return out
		}
		return nullableString(dir)
	}
	return nil
}
