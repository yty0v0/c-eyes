//go:build linux

package startupscan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

var (
	systemdUnitDirs = []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
		"/lib/systemd/system",
	}
	systemdWantsGlobs = []string{
		"/etc/systemd/system/*.wants/*.service",
		"/run/systemd/system/*.wants/*.service",
		"/usr/lib/systemd/system/*.wants/*.service",
		"/lib/systemd/system/*.wants/*.service",
	}
)

type startupRecord struct {
	name          string
	levels        [8]int
	hasRunlevel   bool
	hasInitScript bool
	hasSystemd    bool
	systemdOn     bool
	hasXinetd     bool
	xinetdOn      bool
}

func collectStartupItems(ctx context.Context) ([]StartupInfo, error) {
	defaultLevel := detectDefaultInitLevel()
	records := map[string]*startupRecord{}

	for _, item := range collectRunlevelStates() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rec := ensureRecord(records, item.Name)
		rec.hasRunlevel = true
		rec.levels = item.Levels
	}

	for _, name := range listInitScripts() {
		rec := ensureRecord(records, name)
		rec.hasInitScript = true
	}

	for name, enabled := range collectSystemdUnitStates() {
		rec := ensureRecord(records, name)
		rec.hasSystemd = true
		rec.systemdOn = enabled
	}

	for name, enabled := range collectXinetdStates() {
		rec := ensureRecord(records, name)
		rec.hasXinetd = true
		rec.xinetdOn = enabled
	}

	out := make([]StartupInfo, 0, len(records))
	for _, rec := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := StartupInfo{
			Name:   strPtr(rec.name),
			Xinetd: boolPtr(rec.hasXinetd),
		}
		if execPath := detectLinuxStartupExecPath(rec.name, rec.hasXinetd); execPath != nil {
			row.ExecPath = execPath
		}

		if rec.hasRunlevel || rec.hasInitScript {
			row.RC0 = intPtr(rec.levels[0])
			row.RC1 = intPtr(rec.levels[1])
			row.RC2 = intPtr(rec.levels[2])
			row.RC3 = intPtr(rec.levels[3])
			row.RC4 = intPtr(rec.levels[4])
			row.RC5 = intPtr(rec.levels[5])
			row.RC6 = intPtr(rec.levels[6])
			row.RC7 = intPtr(rec.levels[7])
		}

		switch {
		case rec.hasXinetd:
			row.DefaultOpen = boolPtr(rec.xinetdOn)
			if defaultLevel >= 0 {
				row.InitLevel = intPtr(defaultLevel)
			}
		case rec.hasSystemd:
			row.DefaultOpen = boolPtr(rec.systemdOn)
			if rec.systemdOn && defaultLevel >= 0 {
				row.InitLevel = intPtr(defaultLevel)
			}
		case rec.hasRunlevel || rec.hasInitScript:
			row.DefaultOpen = boolPtr(hasEnabledRunlevel(rec.levels))
		}

		if level := inferInitLevel(defaultLevel, rec.levels, rec.hasRunlevel); level >= 0 {
			row.InitLevel = intPtr(level)
		}

		out = append(out, row)
	}

	sort.Slice(out, func(i, j int) bool {
		li := ""
		if out[i].Name != nil {
			li = strings.ToLower(*out[i].Name)
		}
		lj := ""
		if out[j].Name != nil {
			lj = strings.ToLower(*out[j].Name)
		}
		return li < lj
	})

	return out, nil
}

func ensureRecord(records map[string]*startupRecord, name string) *startupRecord {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return &startupRecord{}
	}
	key := strings.ToLower(trimmed)
	if existing, ok := records[key]; ok {
		return existing
	}
	record := &startupRecord{name: trimmed}
	records[key] = record
	return record
}

type runlevelState struct {
	Name   string
	Levels [8]int
}

func collectRunlevelStates() []runlevelState {
	byName := map[string]*runlevelState{}

	for level := 0; level <= 7; level++ {
		dir := fmt.Sprintf("/etc/rc%d.d", level)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name, enabled, ok := parseRunlevelEntryName(entry.Name())
			if !ok {
				continue
			}
			key := strings.ToLower(name)
			state, ok := byName[key]
			if !ok {
				state = &runlevelState{Name: name}
				byName[key] = state
			}
			if enabled {
				state.Levels[level] = 1
			}
		}
	}

	out := make([]runlevelState, 0, len(byName))
	for _, item := range byName {
		out = append(out, *item)
	}
	return out
}

func parseRunlevelEntryName(entry string) (string, bool, bool) {
	trimmed := strings.TrimSpace(entry)
	if len(trimmed) < 2 {
		return "", false, false
	}

	prefix := trimmed[0]
	if prefix != 'S' && prefix != 'K' {
		return "", false, false
	}
	enabled := prefix == 'S'

	idx := 1
	for idx < len(trimmed) && unicode.IsDigit(rune(trimmed[idx])) {
		idx++
	}
	if idx >= len(trimmed) {
		return "", false, false
	}

	name := strings.TrimSpace(trimmed[idx:])
	if name == "" {
		return "", false, false
	}
	name = strings.TrimSuffix(name, ".service")
	if name == "" {
		return "", false, false
	}
	return name, enabled, true
}

func listInitScripts() []string {
	entries, err := os.ReadDir("/etc/init.d")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" || name == "README" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func collectSystemdUnitStates() map[string]bool {
	states := map[string]bool{}

	for _, dir := range systemdUnitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".service") {
				continue
			}
			unit := strings.TrimSuffix(name, ".service")
			if _, ok := states[unit]; !ok {
				states[unit] = false
			}
		}
	}

	for _, pattern := range systemdWantsGlobs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			name := filepath.Base(match)
			if !strings.HasSuffix(name, ".service") {
				continue
			}
			unit := strings.TrimSuffix(name, ".service")
			states[unit] = true
		}
	}

	return states
}

func collectXinetdStates() map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir("/etc/xinetd.d")
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/etc/xinetd.d", entry.Name()))
		if err != nil {
			continue
		}
		out[name] = parseXinetdEnabled(data)
	}
	return out
}

func parseXinetdEnabled(data []byte) bool {
	enabled := true
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		raw := line
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(strings.ToLower(raw), "disable") {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(parts[1]))
		switch value {
		case "yes", "true", "1":
			enabled = false
		case "no", "false", "0":
			enabled = true
		}
	}
	return enabled
}

func detectDefaultInitLevel() int {
	if data, err := os.ReadFile("/etc/inittab"); err == nil {
		if level, ok := parseInitDefaultFromInittab(data); ok {
			return level
		}
	}

	target := resolveDefaultTarget()
	switch target {
	case "graphical.target", "runlevel5.target":
		return 5
	case "multi-user.target", "runlevel3.target":
		return 3
	case "rescue.target", "emergency.target", "runlevel1.target":
		return 1
	}

	if strings.HasPrefix(target, "runlevel") && strings.HasSuffix(target, ".target") {
		lvl := strings.TrimSuffix(strings.TrimPrefix(target, "runlevel"), ".target")
		if parsed, err := strconv.Atoi(lvl); err == nil && parsed >= 0 && parsed <= 7 {
			return parsed
		}
	}

	return -1
}

func parseInitDefaultFromInittab(data []byte) (int, bool) {
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.Split(raw, ":")
		if len(parts) < 4 {
			continue
		}
		if strings.TrimSpace(parts[2]) != "initdefault" {
			continue
		}
		level, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || level < 0 || level > 7 {
			continue
		}
		return level, true
	}
	return 0, false
}

func resolveDefaultTarget() string {
	paths := []string{
		"/etc/systemd/system/default.target",
		"/usr/lib/systemd/system/default.target",
		"/lib/systemd/system/default.target",
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err == nil {
				return filepath.Base(target)
			}
		}
	}
	return ""
}

func inferInitLevel(defaultLevel int, levels [8]int, hasRunlevel bool) int {
	if !hasRunlevel {
		return -1
	}
	if defaultLevel >= 0 && defaultLevel <= 7 && levels[defaultLevel] == 1 {
		return defaultLevel
	}
	for i := 0; i <= 7; i++ {
		if levels[i] == 1 {
			return i
		}
	}
	if defaultLevel >= 0 && defaultLevel <= 7 {
		return defaultLevel
	}
	return -1
}

func hasEnabledRunlevel(levels [8]int) bool {
	for _, value := range levels {
		if value == 1 {
			return true
		}
	}
	return false
}

func detectLinuxStartupExecPath(name string, isXinetd bool) *string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return nil
	}

	candidates := make([]string, 0, 6)
	candidates = append(candidates, filepath.Join("/etc/init.d", trimmed))
	if isXinetd {
		candidates = append(candidates, filepath.Join("/etc/xinetd.d", trimmed))
	}
	for _, dir := range systemdUnitDirs {
		candidates = append(candidates, filepath.Join(dir, trimmed+".service"))
	}

	for _, path := range candidates {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		cleaned := filepath.Clean(path)
		return &cleaned
	}
	return nil
}
