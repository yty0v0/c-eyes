package jarpackagescan

import (
	"path/filepath"
	"sort"
	"strings"

	"edrsystem/internal/filterutil"
)

func stringContainsAnyFold(value string, needles []string) bool {
	return filterutil.ContainsAnyFold(value, needles)
}

func int64InSlice(val int64, list []int64) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func intInSlice(val int, list []int) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
}

func boolInSlice(val bool, list []bool) bool {
	for _, item := range list {
		if item == val {
			return true
		}
	}
	return false
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
	return nullableString(*v)
}

func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	return intPtr(*v)
}

func cloneInt64Ptr(v *int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v)
}

func cloneBoolPtr(v *bool) *bool {
	if v == nil {
		return nil
	}
	return boolPtr(*v)
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

func firstNonNilString(a, b *string) *string {
	if clone := cloneStringPtr(a); clone != nil {
		return clone
	}
	return cloneStringPtr(b)
}

func firstNonNilInt(a, b *int) *int {
	if clone := cloneIntPtr(a); clone != nil {
		return clone
	}
	return cloneIntPtr(b)
}

func firstNonNilInt64(a, b *int64) *int64 {
	if clone := cloneInt64Ptr(a); clone != nil {
		return clone
	}
	return cloneInt64Ptr(b)
}

func firstNonNilBool(a, b *bool) *bool {
	if clone := cloneBoolPtr(a); clone != nil {
		return clone
	}
	return cloneBoolPtr(b)
}

func normalizePath(path string) *string {
	trimmed := strings.TrimSpace(strings.Trim(path, `"'`))
	if trimmed == "" {
		return nil
	}
	return nullableString(filepath.Clean(trimmed))
}

func splitCommandLineLoose(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 8)
	var b strings.Builder
	quote := rune(0)
	flush := func() {
		if b.Len() == 0 {
			return
		}
		out = append(out, b.String())
		b.Reset()
	}
	for _, r := range raw {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
			continue
		}
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	return out
}
