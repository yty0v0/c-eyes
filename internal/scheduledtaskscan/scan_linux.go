//go:build linux

package scheduledtaskscan

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var linuxCronSystemFiles = []string{
	"/etc/crontab",
}

var linuxCronSystemDirs = []string{
	"/etc/cron.d",
}

var linuxCronUserDirs = []string{
	"/var/spool/cron",
	"/var/spool/cron/crontabs",
}

var linuxAtDirs = []string{
	"/var/spool/at",
	"/var/spool/atjobs",
}

func collectScheduledTasks(ctx context.Context) ([]ScheduledTaskInfo, error) {
	rows := make([]ScheduledTaskInfo, 0)
	var taskID int64 = 1

	appendRow := func(row ScheduledTaskInfo) {
		row.TaskID = int64Ptr(taskID)
		taskID++
		rows = append(rows, row)
	}

	for _, path := range linuxCronSystemFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		items, err := parseCronFile(path, true, "")
		if err != nil {
			continue
		}
		for _, item := range items {
			appendRow(item)
		}
	}

	for _, dir := range linuxCronSystemDirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			items, err := parseCronFile(path, true, "")
			if err != nil {
				continue
			}
			for _, item := range items {
				appendRow(item)
			}
		}
	}

	for _, dir := range linuxCronUserDirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			owner := entry.Name()
			path := filepath.Join(dir, entry.Name())
			items, err := parseCronFile(path, false, owner)
			if err != nil {
				continue
			}
			for _, item := range items {
				appendRow(item)
			}
		}
	}

	for _, dir := range linuxAtDirs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			row, ok := parseAtJob(path, entry.Name())
			if !ok {
				continue
			}
			appendRow(row)
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

func parseCronFile(path string, systemStyle bool, owner string) ([]ScheduledTaskInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	rows := make([]ScheduledTaskInfo, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "@") {
			parts := strings.Fields(line)
			if len(parts) > 0 && strings.Contains(parts[0], "=") {
				continue
			}
		}

		schedule, userName, command, ok := parseCronLine(line, systemStyle, owner)
		if !ok {
			continue
		}

		commandPath := parseExecutableFromCommand(command)
		tt := "CRONTAB"
		row := ScheduledTaskInfo{
			User:      nullableString(userName),
			ExecTime:  nullableString(schedule),
			ExecPath:  nullableString(commandPath),
			Conf:      strPtr(path),
			TaskTime:  timePtr(info.ModTime()),
			TaskType:  strPtr(tt),
			CrondOpen: boolPtr(true),
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rows, nil
}

func parseCronLine(line string, systemStyle bool, owner string) (schedule string, userName string, command string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", "", false
	}

	if strings.HasPrefix(fields[0], "@") {
		schedule = fields[0]
		if systemStyle {
			if len(fields) < 3 {
				return "", "", "", false
			}
			userName = fields[1]
			command = strings.Join(fields[2:], " ")
		} else {
			if len(fields) < 2 {
				return "", "", "", false
			}
			userName = owner
			command = strings.Join(fields[1:], " ")
		}
		return schedule, userName, command, true
	}

	if systemStyle {
		if len(fields) < 7 {
			return "", "", "", false
		}
		schedule = strings.Join(fields[0:5], " ")
		userName = fields[5]
		command = strings.Join(fields[6:], " ")
	} else {
		if len(fields) < 6 {
			return "", "", "", false
		}
		schedule = strings.Join(fields[0:5], " ")
		userName = owner
		command = strings.Join(fields[5:], " ")
	}

	return schedule, userName, command, true
}

func parseAtJob(path string, fileName string) (ScheduledTaskInfo, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ScheduledTaskInfo{}, false
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ScheduledTaskInfo{}, false
	}

	commandPath := parseATCommand(string(data))
	userName := ownerFromFileInfo(info)
	taskType := inferLinuxAtTaskType(fileName)
	execTime := info.ModTime().Format(time.RFC3339)

	row := ScheduledTaskInfo{
		User:      nullableString(userName),
		ExecTime:  strPtr(execTime),
		ExecPath:  nullableString(commandPath),
		Conf:      strPtr(path),
		TaskTime:  timePtr(info.ModTime()),
		TaskType:  strPtr(taskType),
		CrondOpen: boolPtr(true),
	}
	return row, true
}

func inferLinuxAtTaskType(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(lower, "batch") || strings.HasSuffix(lower, ".b") {
		return "BATCH"
	}
	return "AT"
}

func parseATCommand(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "/") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 && strings.Contains(parts[0], "=") {
				continue
			}
		}
		return parseExecutableFromCommand(trimmed)
	}
	return ""
}

func ownerFromFileInfo(info os.FileInfo) string {
	sys := info.Sys()
	stat, ok := sys.(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	u, err := user.LookupId(uid)
	if err != nil {
		return uid
	}
	if strings.TrimSpace(u.Username) == "" {
		return uid
	}
	return u.Username
}

func timePtr(v time.Time) *time.Time {
	vv := v.UTC()
	return &vv
}
