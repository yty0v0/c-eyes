//go:build windows

package scheduledtaskscan

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

type windowsTaskXML struct {
	XMLName    xml.Name                 `xml:"Task"`
	Actions    windowsTaskActions       `xml:"Actions"`
	Settings   windowsTaskSettings      `xml:"Settings"`
	Triggers   windowsTaskTriggersGroup `xml:"Triggers"`
	Principals struct {
		Principal []struct {
			UserID string `xml:"UserId"`
		} `xml:"Principal"`
	} `xml:"Principals"`
}

type windowsTaskActions struct {
	Exec []struct {
		Command   string `xml:"Command"`
		Arguments string `xml:"Arguments"`
	} `xml:"Exec"`
}

type windowsTaskSettings struct {
	Enabled string `xml:"Enabled"`
}

type windowsTaskTriggersGroup struct {
	Calendar []windowsTaskTrigger `xml:"CalendarTrigger"`
	Time     []windowsTaskTrigger `xml:"TimeTrigger"`
	Logon    []windowsTaskTrigger `xml:"LogonTrigger"`
	Boot     []windowsTaskTrigger `xml:"BootTrigger"`
	Event    []windowsTaskTrigger `xml:"EventTrigger"`
	Idle     []windowsTaskTrigger `xml:"IdleTrigger"`
}

type windowsTaskTrigger struct {
	StartBoundary string `xml:"StartBoundary"`
}

func collectScheduledTasks(ctx context.Context) ([]ScheduledTaskInfo, error) {
	rows := make([]ScheduledTaskInfo, 0)
	var taskID int64 = 1

	tasksRoot := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks")
	if strings.TrimSpace(tasksRoot) == "" {
		tasksRoot = `C:\Windows\System32\Tasks`
	}

	_ = filepath.WalkDir(tasksRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		row, ok := parseWindowsXMLTask(path)
		if !ok {
			return nil
		}
		row.TaskID = int64Ptr(taskID)
		taskID++
		rows = append(rows, row)
		return nil
	})

	legacyDir := filepath.Join(os.Getenv("WINDIR"), "Tasks")
	if strings.TrimSpace(legacyDir) == "" {
		legacyDir = `C:\Windows\Tasks`
	}
	entries, err := os.ReadDir(legacyDir)
	if err == nil {
		for _, entry := range entries {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(legacyDir, entry.Name())
			info, statErr := entry.Info()
			if statErr != nil {
				continue
			}
			typeVal := "AT"
			if strings.HasSuffix(strings.ToLower(entry.Name()), ".bat") || strings.HasSuffix(strings.ToLower(entry.Name()), ".cmd") {
				typeVal = "BATCH"
			}
			execTime := info.ModTime().Format(time.RFC3339)
			rows = append(rows, ScheduledTaskInfo{
				ExecTime:  strPtr(execTime),
				Conf:      strPtr(path),
				TaskTime:  timePtr(info.ModTime()),
				TaskType:  strPtr(typeVal),
				CrondOpen: boolPtr(true),
				TaskID:    int64Ptr(taskID),
			})
			taskID++
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].TaskID == nil || rows[j].TaskID == nil {
			return i < j
		}
		return *rows[i].TaskID < *rows[j].TaskID
	})

	return rows, nil
}

func parseWindowsXMLTask(path string) (ScheduledTaskInfo, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ScheduledTaskInfo{}, false
	}

	decoded, ok := decodeTaskXML(data)
	if !ok {
		decoded = data
	}
	decoded = normalizeXMLDeclEncoding(decoded)

	var doc windowsTaskXML
	if err := xml.Unmarshal(decoded, &doc); err != nil {
		return ScheduledTaskInfo{}, false
	}

	cmd, args := firstExecAction(doc.Actions)
	execPath := parseExecutableFromCommand(strings.TrimSpace(strings.TrimSpace(cmd) + " " + strings.TrimSpace(args)))
	execTime := firstTriggerDescription(doc.Triggers)
	startTime := firstTriggerTime(doc.Triggers)
	taskType := inferWindowsTaskType(execPath, path)
	enabled := parseWindowsEnabled(doc.Settings.Enabled)
	userName := firstPrincipalUser(doc)

	row := ScheduledTaskInfo{
		User:      nullableString(userName),
		ExecTime:  nullableString(execTime),
		ExecPath:  nullableString(execPath),
		Conf:      strPtr(path),
		TaskType:  strPtr(taskType),
		CrondOpen: boolPtr(enabled),
	}
	if !startTime.IsZero() {
		row.TaskTime = timePtr(startTime)
	}
	return row, true
}

func firstExecAction(actions windowsTaskActions) (string, string) {
	for _, item := range actions.Exec {
		if strings.TrimSpace(item.Command) == "" && strings.TrimSpace(item.Arguments) == "" {
			continue
		}
		return item.Command, item.Arguments
	}
	return "", ""
}

func firstTriggerTime(group windowsTaskTriggersGroup) time.Time {
	all := [][]windowsTaskTrigger{group.Time, group.Calendar, group.Logon, group.Boot, group.Event, group.Idle}
	for _, list := range all {
		for _, trigger := range list {
			if strings.TrimSpace(trigger.StartBoundary) == "" {
				continue
			}
			if parsed, err := parseWindowsBoundaryTime(trigger.StartBoundary); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func firstTriggerDescription(group windowsTaskTriggersGroup) string {
	all := [][]windowsTaskTrigger{group.Time, group.Calendar, group.Logon, group.Boot, group.Event, group.Idle}
	for _, list := range all {
		for _, trigger := range list {
			if strings.TrimSpace(trigger.StartBoundary) != "" {
				return strings.TrimSpace(trigger.StartBoundary)
			}
		}
	}
	return ""
}

func parseWindowsBoundaryTime(value string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, os.ErrInvalid
}

func parseWindowsEnabled(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return true
	}
	switch trimmed {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return true
	}
}

func firstPrincipalUser(doc windowsTaskXML) string {
	for _, principal := range doc.Principals.Principal {
		if strings.TrimSpace(principal.UserID) != "" {
			return strings.TrimSpace(principal.UserID)
		}
	}
	return ""
}

func inferWindowsTaskType(execPath, sourcePath string) string {
	lowerExec := strings.ToLower(strings.TrimSpace(execPath))
	if strings.HasSuffix(lowerExec, ".bat") || strings.HasSuffix(lowerExec, ".cmd") {
		return "BATCH"
	}
	lowerSource := strings.ToLower(strings.TrimSpace(sourcePath))
	if strings.Contains(lowerSource, `\windows\tasks\`) || strings.HasSuffix(lowerSource, ".job") {
		return "AT"
	}
	return "AT"
}

func decodeTaskXML(data []byte) ([]byte, bool) {
	if len(data) < 2 {
		return nil, false
	}
	if data[0] == 0xFF && data[1] == 0xFE {
		u16 := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			u16 = append(u16, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		runes := utf16.Decode(u16)
		return []byte(string(runes)), true
	}
	if data[0] == 0xFE && data[1] == 0xFF {
		u16 := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			u16 = append(u16, binary.BigEndian.Uint16(data[i:i+2]))
		}
		runes := utf16.Decode(u16)
		return []byte(string(runes)), true
	}
	return nil, false
}

// normalizeXMLDeclEncoding rewrites UTF-16 XML declarations after we decode to UTF-8 bytes.
func normalizeXMLDeclEncoding(data []byte) []byte {
	text := string(data)
	// encoding="UTF-16" / encoding='utf-16' -> UTF-8
	reDouble := regexp.MustCompile(`(?i)encoding\s*=\s*"utf-16"`)
	reSingle := regexp.MustCompile(`(?i)encoding\s*=\s*'utf-16'`)
	text = reDouble.ReplaceAllString(text, `encoding="UTF-8"`)
	text = reSingle.ReplaceAllString(text, `encoding="UTF-8"`)
	return []byte(text)
}

func timePtr(v time.Time) *time.Time {
	vv := v.UTC()
	return &vv
}
