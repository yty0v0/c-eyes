//go:build !windows

package benchmark

import (
	"context"
	"edrsystem/internal/accountscan"
	"edrsystem/internal/processscan"
	"edrsystem/internal/startupscan"
	"edrsystem/internal/usergroupscan"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func scanUnixNativeBenchmark(ctx context.Context, template Template, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	if template == TemplateWindows {
		return ScanResult{}, false, nil
	}

	ruleSet, err := loadBenchmarkRuleSet(template)
	if err != nil {
		return ScanResult{}, true, err
	}
	ruleIndex := buildBenchmarkRuleIndex(ruleSet)

	profile, err := nativeProfileForTemplate(template)
	if err != nil {
		return ScanResult{}, true, err
	}

	var (
		accounts   []accountscan.AccountInfo
		groups     []usergroupscan.UserGroupInfo
		processes  []processscan.ProcessInfo
		startups   []startupscan.StartupInfo
		interfaces []unixInterfaceRecord
		disks      []unixFilesystemRecord
		sensitive  []unixSensitiveFileRecord
	)
	results := make([]benchmarkCheckResult, 0, len(profile.checks))
	for idx, check := range profile.checks {
		select {
		case <-ctx.Done():
			return ScanResult{}, true, ctx.Err()
		default:
		}

		notifyProgress(progress, benchmarkRangedProgress(benchmarkProgressExecuteStart, benchmarkProgressExecuteEnd, idx+1, len(profile.checks)), benchmarkProgressTotalSteps, "execute checks")

		actual, runErr := executeNativeCheckCommand(ctx, template, check)
		actual = keepFirstNonEmptyLines(actual, check.limitNonEmptyLines)
		actual = normalizeTrim(actual)
		result := benchmarkCheckResult{
			ID:          check.id,
			SectionType: "display",
			Command:     check.command,
			Actual:      actual,
			Evidence:    actual,
			Eval: map[string]any{
				"actual": actual,
			},
		}
		switch template {
		case TemplateLinux:
			switch check.id {
			case "0":
				result.Eval["present"] = strings.TrimSpace(actual) != ""
			case "1":
				if accounts == nil {
					if scan, err := accountscan.Scan(ctx, accountscan.AccountScanParams{}); err == nil {
						accounts = scan.Rows
					}
				}
				if len(accounts) > 0 {
					result = shapeUnixAccountsResult(result, accounts)
				}
			case "2":
				if groups == nil {
					if scan, err := usergroupscan.Scan(ctx, usergroupscan.UserGroupScanParams{}); err == nil {
						groups = scan.Rows
					}
				}
				if len(groups) > 0 {
					result = shapeUnixGroupsResult(result, groups)
				}
			case "3":
				result = shapeUnixShadowSummary(result)
			case "4":
				if sensitive == nil {
					sensitive = collectUnixSensitiveFiles([]string{"/etc/shadow", "/etc/gshadow", "/etc/passwd"})
				}
				if len(sensitive) > 0 {
					result = shapeUnixSensitiveFilesResult(result, sensitive)
				}
			case "5":
				if value, err := collectUnixConfigSummary(template, check.id); err == nil && strings.TrimSpace(value.Actual) != "" {
					result = value
				}
			case "6":
				if startups == nil {
					if scan, err := startupscan.Scan(ctx, startupscan.StartupScanParams{}); err == nil {
						startups = scan.Rows
					}
				}
				if len(startups) > 0 {
					result = shapeUnixServicesResult(result, startups)
				}
			case "7":
				if interfaces == nil {
					if rows, err := collectUnixInterfaces(); err == nil {
						interfaces = rows
					}
				}
				if len(interfaces) > 0 {
					result = shapeUnixInterfacesResult(result, interfaces)
				}
			case "10":
				if disks == nil {
					if rows, err := collectUnixFilesystems(); err == nil {
						disks = rows
					}
				}
				if len(disks) > 0 {
					result = shapeUnixFilesystemsResult(result, disks)
				}
			case "15":
				if processes == nil {
					if rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{}); err == nil {
						processes = rows
					}
				}
				if len(processes) > 0 {
					result = shapeUnixProcessesResult(result, processes)
				}
			case "8", "9", "11", "12", "14", "16", "17", "19", "20", "22":
				if value, err := collectUnixConfigSummary(template, check.id); err == nil {
					result = value
				}
			case "13":
				result.Actual = "无需清理临时工件"
				result.Evidence = result.Actual
				result.Eval["present"] = true
			}
		case TemplateEulerOS:
			switch check.id {
			case "0":
				result.Eval["present"] = strings.TrimSpace(actual) != ""
			case "1":
				if accounts == nil {
					if scan, err := accountscan.Scan(ctx, accountscan.AccountScanParams{}); err == nil {
						accounts = scan.Rows
					}
				}
				if len(accounts) > 0 {
					result = shapeUnixAccountsResult(result, accounts)
				}
			case "2":
				if groups == nil {
					if scan, err := usergroupscan.Scan(ctx, usergroupscan.UserGroupScanParams{}); err == nil {
						groups = scan.Rows
					}
				}
				if len(groups) > 0 {
					result = shapeUnixGroupsResult(result, groups)
				}
			case "4":
				if startups == nil {
					if scan, err := startupscan.Scan(ctx, startupscan.StartupScanParams{}); err == nil {
						startups = scan.Rows
					}
				}
				if len(startups) > 0 {
					result = shapeUnixServicesResult(result, startups)
				}
			case "5":
				if value, err := collectUnixConfigSummary(template, check.id); err == nil {
					result = value
				}
			case "6":
				if interfaces == nil {
					if rows, err := collectUnixInterfaces(); err == nil {
						interfaces = rows
					}
				}
				if len(interfaces) > 0 {
					result = shapeUnixInterfacesResult(result, interfaces)
				}
			case "10":
				if disks == nil {
					if rows, err := collectUnixFilesystems(); err == nil {
						disks = rows
					}
				}
				if len(disks) > 0 {
					result = shapeUnixFilesystemsResult(result, disks)
				}
			case "3", "8", "9", "11", "14", "18":
				if value, err := collectUnixConfigSummary(template, check.id); err == nil {
					result = value
				}
			case "7":
				result.Actual = "无需清理临时工件"
				result.Evidence = result.Actual
				result.Eval["present"] = true
			}
		case TemplateKylin:
			switch check.id {
			case "7":
				result.Eval["present"] = strings.TrimSpace(actual) != ""
			case "1":
				if startups == nil {
					if scan, err := startupscan.Scan(ctx, startupscan.StartupScanParams{}); err == nil {
						startups = scan.Rows
					}
				}
				if len(startups) > 0 {
					result = shapeUnixServicesResult(result, startups)
				}
			case "3":
				if sensitive == nil {
					sensitive = collectUnixSensitiveFiles([]string{"/etc/shadow", "/etc/gshadow", "/etc/passwd"})
				}
				if len(sensitive) > 0 {
					result = shapeUnixSensitiveFilesResult(result, sensitive)
				}
			case "4":
				result = shapeUnixShadowSummary(result)
			case "6":
				if groups == nil {
					if scan, err := usergroupscan.Scan(ctx, usergroupscan.UserGroupScanParams{}); err == nil {
						groups = scan.Rows
					}
				}
				if len(groups) > 0 {
					result = shapeUnixGroupsResult(result, groups)
				}
			case "10":
				if disks == nil {
					if rows, err := collectUnixFilesystems(); err == nil {
						disks = rows
					}
				}
				if len(disks) > 0 {
					result = shapeUnixFilesystemsResult(result, disks)
				}
			case "11":
				if interfaces == nil {
					if rows, err := collectUnixInterfaces(); err == nil {
						interfaces = rows
					}
				}
				if len(interfaces) > 0 {
					result = shapeUnixInterfacesResult(result, interfaces)
				}
			case "14":
				if processes == nil {
					if rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{}); err == nil {
						processes = rows
					}
				}
				if len(processes) > 0 {
					result = shapeUnixProcessesResult(result, processes)
				}
			case "5", "8", "12", "13", "15":
				if value, err := collectUnixConfigSummary(template, check.id); err == nil {
					result = value
				}
			case "2":
				result.Actual = "无需清理临时工件"
				result.Evidence = result.Actual
				result.Eval["present"] = true
			}
		}
		result = shapeUnixBenchmarkResult(template, result)
		executionErrorDetected := strings.Contains(strings.ToLower(result.Evidence), "not found") || strings.Contains(strings.ToLower(result.Actual), "not found")
		if runErr != nil {
			message := fmt.Sprintf("collector execution failed: %v", runErr)
			if result.Actual == "" {
				result.Actual = message
			}
			result.Evidence = result.Actual
			result.Status = statusAssessment{
				Status:          "fail",
				Evaluated:       true,
				StatusReason:    "execution_error",
				ExecutionStatus: "error",
			}
			executionErrorDetected = true
		}
		if rule, ok := ruleIndex[check.id]; ok {
			applyBenchmarkRule(rule, &result)
		} else if result.Status == (statusAssessment{}) {
			result.Status = deriveStatusAssessment(template, check.id, result.Actual)
		}
		if strings.Contains(result.ID, "-META-") {
			result.Status = statusAssessment{
				Status:          "unknown",
				Evaluated:       false,
				StatusReason:    "informational_check",
				ExecutionStatus: "ok",
			}
		}
		if executionErrorDetected {
			result.Status = statusAssessment{
				Status:          "fail",
				Evaluated:       true,
				StatusReason:    "execution_error",
				ExecutionStatus: "error",
			}
		}
		if result.Status.ExecutionStatus == "" {
			result.Status.ExecutionStatus = "ok"
		}
		results = append(results, result)
	}

	notifyProgress(progress, benchmarkProgressCollectDone, benchmarkProgressTotalSteps, "assemble results")
	host := resolveHostIdentity()
	rows := make([]Row, 0, len(results))
	for _, result := range results {
		rows = append(rows, Row{
			Host:            host,
			Template:        string(template),
			CheckID:         result.ID,
			CheckName:       firstNonEmpty(result.Name, result.ID),
			Category:        firstNonEmpty(result.Category, result.SectionType),
			Description:     result.Description,
			Status:          result.Status.Status,
			Evaluated:       result.Status.Evaluated,
			StatusReason:    result.Status.StatusReason,
			ExecutionStatus: result.Status.ExecutionStatus,
			Severity:        result.Severity,
			Recommendation:  result.Recommendation,
			Expected:        result.Expected,
			Actual:          result.Actual,
			Evidence:        result.Evidence,
			Command:         result.Command,
		})
	}
	notifyProgress(progress, benchmarkProgressParseEnd, benchmarkProgressTotalSteps, "finalize results")

	return ScanResult{
		Template: string(template),
		Metadata: Metadata{
			UUID:            profile.uuid,
			TemplateTime:    profile.templateTime,
			Product:         "BVS",
			TemplateName:    benchmarkTemplateDisplayName(template),
			TemplateVersion: "V6.0R03F02.0007",
			Industry:        "等级保护2.0",
			SystemVersion:   "V6.0R03F03SP07",
			Hash:            "42F1-91D7-00CD-EE46",
		},
		Summary: summarize(rows),
		Rows:    rows,
	}, true, nil
}

func benchmarkTemplateDisplayName(template Template) string {
	switch template {
	case TemplateLinux:
		return "Linux 配置规范_S1A1G1"
	case TemplateEulerOS:
		return "EulerOS 配置规范_S1A1G1"
	case TemplateKylin:
		return "银河麒麟 配置规范_S1A1G1"
	case TemplateWindows:
		return "Windows 配置规范_S1A1G1"
	default:
		return string(template)
	}
}

func normalizeTrim(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.TrimSpace(value)
}

func shapeUnixBenchmarkResult(template Template, result benchmarkCheckResult) benchmarkCheckResult {
	if result.Eval == nil {
		result.Eval = map[string]any{}
	}
	actual := strings.TrimSpace(result.Actual)
	lines := nonEmptyLines(actual)
	summary := actual
	if len(lines) > 0 {
		switch result.ID {
		case "0":
			summary = firstLine(lines)
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "17", "18", "19", "20", "21", "22":
			summary = summarizeUnixOutput(template, result.ID, lines)
		}
	}
	result.Actual = summary
	if strings.TrimSpace(result.Evidence) == "" {
		result.Evidence = actual
	}
	result.Eval["line_count"] = len(lines)
	result.Eval["actual"] = summary
	return result
}

func summarizeUnixOutput(template Template, checkID string, lines []string) string {
	label := unixCheckLabel(template, checkID)
	if len(lines) == 0 {
		return ""
	}
	if len(lines) == 1 {
		return lines[0]
	}
	preview := lines
	if len(preview) > 3 {
		preview = preview[:3]
	}
	suffix := ""
	if len(lines) > len(preview) {
		suffix = " ..."
	}
	return strconv.Itoa(len(lines)) + " " + label + ": " + strings.Join(preview, " | ") + suffix
}

func unixCheckLabel(template Template, checkID string) string {
	switch template {
	case TemplateLinux:
		return linuxCheckLabel(checkID)
	case TemplateEulerOS:
		return eulerCheckLabel(checkID)
	case TemplateKylin:
		return kylinCheckLabel(checkID)
	default:
		return "entries"
	}
}

func linuxCheckLabel(checkID string) string {
	switch checkID {
	case "0":
		return "kernel entries"
	case "1":
		return "account entries"
	case "2":
		return "group entries"
	case "3":
		return "shadow entries"
	case "4":
		return "file attribute entries"
	case "5":
		return "terminal entries"
	case "6":
		return "service entries"
	case "7":
		return "interface entries"
	case "8":
		return "login entries"
	case "9":
		return "log config entries"
	case "10":
		return "filesystem entries"
	case "11":
		return "failed login entries"
	case "12":
		return "log summary entries"
	case "13":
		return "cleanup entries"
	case "14":
		return "network connection entries"
	case "15":
		return "process entries"
	case "17":
		return "ftp chroot entries"
	case "18":
		return "release entries"
	case "19":
		return "ftp banner file entries"
	case "20":
		return "ftp access entries"
	case "21":
		return "rpm package entries"
	case "22":
		return "release entries"
	default:
		return "entries"
	}
}

func eulerCheckLabel(checkID string) string {
	switch checkID {
	case "0":
		return "kernel entries"
	case "1":
		return "account entries"
	case "2":
		return "group entries"
	case "3":
		return "log entries"
	case "4":
		return "service entries"
	case "5":
		return "terminal entries"
	case "6":
		return "interface entries"
	case "7":
		return "cleanup entries"
	case "8":
		return "login entries"
	case "9":
		return "ssh access entries"
	case "10":
		return "filesystem entries"
	case "11":
		return "failed login entries"
	case "18":
		return "release entries"
	case "21":
		return "rpm package entries"
	default:
		return "entries"
	}
}

func kylinCheckLabel(checkID string) string {
	switch checkID {
	case "1":
		return "service entries"
	case "2":
		return "cleanup entries"
	case "3":
		return "file attribute entries"
	case "4":
		return "shadow entries"
	case "5":
		return "failed login entries"
	case "6":
		return "group entries"
	case "7":
		return "kernel entries"
	case "8":
		return "release entries"
	case "9":
		return "rpm package entries"
	case "10":
		return "filesystem entries"
	case "11":
		return "interface entries"
	case "12":
		return "login entries"
	case "13":
		return "log entries"
	case "14":
		return "process entries"
	case "15":
		return "network connection entries"
	default:
		return "entries"
	}
}

func nonEmptyLines(value string) []string {
	rawLines := strings.Split(value, "\n")
	out := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func firstLine(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

func shapeUnixAccountsResult(result benchmarkCheckResult, rows []accountscan.AccountInfo) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	rootPresent := false
	for _, row := range rows {
		if row.Name != nil && strings.TrimSpace(*row.Name) != "" {
			names = append(names, strings.TrimSpace(*row.Name))
		}
		if row.Root != nil && *row.Root {
			rootPresent = true
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("共采集到 %d 个本地账户，root 账户存在=%t", len(names), rootPresent)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["account_count"] = len(names)
	result.Eval["root_account_present"] = rootPresent
	result.Eval["present"] = len(names) > 0
	return result
}

func shapeUnixGroupsResult(result benchmarkCheckResult, rows []usergroupscan.UserGroupInfo) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	privileged := false
	for _, row := range rows {
		if row.Name != nil && strings.TrimSpace(*row.Name) != "" {
			name := strings.TrimSpace(*row.Name)
			names = append(names, name)
			switch strings.ToLower(name) {
			case "root", "wheel", "adm", "sudo":
				privileged = true
			}
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("共采集到 %d 个本地用户组，高权限组存在=%t", len(names), privileged)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["group_count"] = len(names)
	result.Eval["privileged_group_present"] = privileged
	result.Eval["present"] = len(names) > 0
	return result
}

func shapeUnixProcessesResult(result benchmarkCheckResult, rows []processscan.ProcessInfo) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Name != nil && strings.TrimSpace(*row.Name) != "" {
			names = append(names, strings.TrimSpace(*row.Name))
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("共采集到 %d 个运行进程", len(names))
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["process_count"] = len(names)
	result.Eval["present"] = len(names) > 0
	return result
}

func shapeUnixServicesResult(result benchmarkCheckResult, rows []startupscan.StartupInfo) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	autoEnabled := 0
	for _, row := range rows {
		if row.Name != nil && strings.TrimSpace(*row.Name) != "" {
			names = append(names, strings.TrimSpace(*row.Name))
		}
		if row.DefaultOpen != nil && *row.DefaultOpen {
			autoEnabled++
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("共采集到 %d 个服务，其中 %d 个开机启用", len(names), autoEnabled)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["service_count"] = len(names)
	result.Eval["auto_enabled_count"] = autoEnabled
	result.Eval["present"] = len(names) > 0
	return result
}

type unixInterfaceRecord struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func shapeUnixInterfacesResult(result benchmarkCheckResult, rows []unixInterfaceRecord) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	addressCount := 0
	for _, row := range rows {
		if strings.TrimSpace(row.Name) != "" {
			names = append(names, strings.TrimSpace(row.Name))
		}
		addressCount += len(row.Addresses)
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("发现 %d 个活动网络接口，共 %d 个地址", len(names), addressCount)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["interface_count"] = len(names)
	result.Eval["address_count"] = addressCount
	result.Eval["present"] = len(names) > 0
	return result
}

type unixFilesystemRecord struct {
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fs_type"`
	TotalMB    uint64 `json:"total_mb"`
	UsedMB     uint64 `json:"used_mb"`
	AvailMB    uint64 `json:"avail_mb"`
}

type unixSensitiveFileRecord struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
}

func shapeUnixFilesystemsResult(result benchmarkCheckResult, rows []unixFilesystemRecord) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	highestUsed := uint64(0)
	for _, row := range rows {
		if strings.TrimSpace(row.MountPoint) != "" {
			names = append(names, strings.TrimSpace(row.MountPoint))
		}
		if row.TotalMB > 0 {
			usedPct := (row.UsedMB * 100) / row.TotalMB
			if usedPct > highestUsed {
				highestUsed = usedPct
			}
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("发现 %d 个挂载文件系统，最高使用率 %d%%", len(names), highestUsed)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["filesystem_count"] = len(names)
	result.Eval["highest_used_percent"] = int64(highestUsed)
	result.Eval["present"] = len(names) > 0
	return result
}

func shapeUnixSensitiveFilesResult(result benchmarkCheckResult, rows []unixSensitiveFileRecord) benchmarkCheckResult {
	names := make([]string, 0, len(rows))
	protected := 0
	for _, row := range rows {
		if !row.Exists {
			continue
		}
		names = append(names, row.Path+"("+row.Mode+")")
		if strings.HasPrefix(row.Mode, "0") || row.Mode == "400" || row.Mode == "600" {
			protected++
		}
	}
	if len(names) == 0 {
		return result
	}
	result.Actual = fmt.Sprintf("%d/%d 个敏感文件处于受保护状态", protected, len(names))
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["sensitive_file_count"] = len(names)
	result.Eval["protected_file_count"] = protected
	result.Eval["present"] = len(names) > 0
	return result
}

func shapeUnixShadowSummary(result benchmarkCheckResult) benchmarkCheckResult {
	lines := nonEmptyLines(result.Evidence)
	entryCount := 0
	emptyPasswordCount := 0
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		entryCount++
		passwordField := strings.TrimSpace(parts[1])
		if passwordField == "" || passwordField == "!" || passwordField == "*" || passwordField == "!!" {
			continue
		}
		if !strings.HasPrefix(passwordField, "$") {
			emptyPasswordCount++
		}
	}
	result.Actual = fmt.Sprintf("共发现 %d 条影子口令记录，其中 %d 条为弱口令或空口令标记", entryCount, emptyPasswordCount)
	result.Eval["shadow_entry_count"] = entryCount
	result.Eval["empty_password_count"] = emptyPasswordCount
	result.Eval["present"] = entryCount > 0
	return result
}

func collectUnixInterfaces() ([]unixInterfaceRecord, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]unixInterfaceRecord, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		item := unixInterfaceRecord{Name: iface.Name}
		for _, addr := range addrs {
			item.Addresses = append(item.Addresses, addr.String())
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func collectUnixFilesystems() ([]unixFilesystemRecord, error) {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	out := make([]unixFilesystemRecord, 0, 16)
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		mountPoint := fields[1]
		fsType := fields[2]
		if _, ok := seen[mountPoint]; ok {
			continue
		}
		seen[mountPoint] = struct{}{}
		var stat unix.Statfs_t
		if err := unix.Statfs(mountPoint, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize) / (1024 * 1024)
		avail := stat.Bavail * uint64(stat.Bsize) / (1024 * 1024)
		used := total - avail
		out = append(out, unixFilesystemRecord{
			MountPoint: mountPoint,
			FSType:     fsType,
			TotalMB:    total,
			UsedMB:     used,
			AvailMB:    avail,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MountPoint < out[j].MountPoint })
	return out, nil
}

func collectUnixSensitiveFiles(paths []string) []unixSensitiveFileRecord {
	out := make([]unixSensitiveFileRecord, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			out = append(out, unixSensitiveFileRecord{Path: path, Exists: false})
			continue
		}
		rec := unixSensitiveFileRecord{
			Path:   path,
			Exists: true,
			Mode:   fmt.Sprintf("%03o", info.Mode().Perm()),
		}
		if stat, ok := info.Sys().(*unix.Stat_t); ok {
			rec.UID = stat.Uid
			rec.GID = stat.Gid
		}
		out = append(out, rec)
	}
	return out
}

func collectUnixConfigSummary(template Template, checkID string) (benchmarkCheckResult, error) {
	switch template {
	case TemplateLinux:
		switch checkID {
		case "8":
			value, err := readLastOutput(false)
			return configResult(checkID, value, err)
		case "11":
			value, err := readLastOutput(true)
			return configResult(checkID, value, err)
		case "14":
			value, err := readNetstatOutput()
			return configResult(checkID, value, err)
		case "5":
			value, err := readFileIfExists("/etc/securetty", true, 120)
			return configResult(checkID, value, err)
		case "9":
			value, err := readFirstExistingFile([]string{"/etc/syslog.conf", "/etc/syslog-ng/syslog-ng.conf", "/etc/rsyslog.conf"}, true, 120)
			return configResult(checkID, value, err)
		case "12":
			value, err := readFirstExistingFile([]string{"/var/log/syslog", "/var/log/messages"}, false, 20)
			return configResult(checkID, value, err)
		case "16":
			value, err := parseKeyValueFromFiles([]string{"/etc/vsftpd.conf", "/etc/vsftpd/vsftpd.conf"}, "ftpd_banner")
			return configResult(checkID, value, err)
		case "17":
			value, err := readFileIfExists("/etc/vsftpd/chroot_list", true, 120)
			return configResult(checkID, value, err)
		case "19":
			ftpaccess, err := readFileIfExists("/etc/ftpaccess", true, 120)
			if err != nil {
				return benchmarkCheckResult{}, err
			}
			path := ""
			for _, line := range nonEmptyLines(ftpaccess) {
				fields := strings.Fields(line)
				if len(fields) >= 2 && strings.EqualFold(fields[0], "banner") {
					path = fields[1]
					break
				}
			}
			value := ""
			if path != "" {
				value, err = readFileIfExists(path, true, 120)
				if err != nil {
					return benchmarkCheckResult{}, err
				}
			}
			return configResult(checkID, value, nil)
		case "20":
			value, err := readFileIfExists("/etc/ftpaccess", true, 120)
			return configResult(checkID, value, err)
		case "22":
			value, err := collectUnixReleaseInfo(template)
			return configResult(checkID, value, err)
		}
	case TemplateEulerOS:
		switch checkID {
		case "3":
			value, err := readFirstExistingFile([]string{"/var/log/messages"}, false, 20)
			return configResult(checkID, value, err)
		case "5":
			value, err := readFileIfExists("/etc/securetty", true, 120)
			return configResult(checkID, value, err)
		case "8":
			value, err := readLastOutput(false)
			return configResult(checkID, value, err)
		case "11":
			value, err := readLastOutput(true)
			return configResult(checkID, value, err)
		case "14":
			value, err := readNetstatOutput()
			return configResult(checkID, value, err)
		case "9":
			value, err := filterLinesContaining("/etc/ssh/sshd_config", []string{"AllowUsers", "DenyUsers"}, 120)
			return configResult(checkID, value, err)
		case "18":
			value, err := collectUnixReleaseInfo(template)
			return configResult(checkID, value, err)
		}
	case TemplateKylin:
		switch checkID {
		case "5":
			value, err := readLastOutput(true)
			return configResult(checkID, value, err)
		case "8":
			value, err := collectUnixReleaseInfo(template)
			return configResult(checkID, value, err)
		case "12":
			value, err := readLastOutput(false)
			return configResult(checkID, value, err)
		case "13":
			value, err := readFirstExistingFile([]string{"/var/log/syslog", "/var/log/messages"}, false, 20)
			return configResult(checkID, value, err)
		case "15":
			value, err := readNetstatOutput()
			return configResult(checkID, value, err)
		}
	}
	return benchmarkCheckResult{}, nil
}

func configResult(checkID, value string, err error) (benchmarkCheckResult, error) {
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	value = normalizeTrim(value)
	summary := summarizeConfigValue(checkID, value)
	result := benchmarkCheckResult{
		ID:          checkID,
		SectionType: "display",
		Actual:      summary,
		Evidence:    value,
		Eval: map[string]any{
			"actual":     summary,
			"line_count": len(nonEmptyLines(value)),
		},
	}
	if strings.TrimSpace(value) != "" {
		result.Eval["present"] = true
	} else {
		result.Eval["present"] = false
	}
	applyConfigMetrics(checkID, value, result.Eval)
	if checkID == "8" || checkID == "11" || checkID == "14" || checkID == "15" {
		if count, ok := lookupEvalInt(result.Eval, "entry_count"); ok && count > 0 {
			result.Eval["present"] = true
		}
		if count, ok := lookupEvalInt(result.Eval, "listen_count"); ok && count > 0 {
			result.Eval["present"] = true
		}
	}
	return result, nil
}

func applyConfigMetrics(checkID, value string, eval map[string]any) {
	lines := nonEmptyLines(value)
	switch checkID {
	case "8", "11":
		count := len(lines)
		for _, line := range lines {
			lower := strings.ToLower(strings.TrimSpace(line))
			if strings.Contains(lower, "begins") && count > 0 {
				count--
			}
		}
		eval["entry_count"] = count
	case "9":
		eval["rule_count"] = len(lines)
	case "12", "13", "3":
		eval["log_line_count"] = len(lines)
	case "14", "15":
		listen := 0
		established := 0
		for _, line := range lines {
			upper := strings.ToUpper(line)
			if strings.Contains(upper, "LISTEN") {
				listen++
			}
			if strings.Contains(upper, "ESTABLISHED") {
				established++
			}
		}
		eval["listen_count"] = listen
		eval["established_count"] = established
	case "17":
		eval["entry_count"] = len(lines)
	case "20":
		eval["rule_count"] = len(lines)
	}
}

func summarizeConfigValue(checkID, value string) string {
	lines := nonEmptyLines(value)
	switch checkID {
	case "5":
		if len(lines) == 0 {
			return "未配置安全终端规则"
		}
		return fmt.Sprintf("已配置 %d 条安全终端规则", len(lines))
	case "8":
		if len(lines) == 0 {
			return "未采集到最近登录记录"
		}
		return fmt.Sprintf("采集到 %d 条最近登录记录", len(lines))
	case "9":
		if len(lines) == 0 {
			return "未配置访问控制规则"
		}
		return fmt.Sprintf("已配置 %d 条访问控制规则", len(lines))
	case "11":
		if len(lines) == 0 {
			return "未采集到失败登录记录"
		}
		return fmt.Sprintf("采集到 %d 条失败登录记录", len(lines))
	case "12", "13", "3":
		if len(lines) == 0 {
			return "未采集到日志摘要"
		}
		return fmt.Sprintf("采集到 %d 条日志摘要", len(lines))
	case "14", "15":
		if len(lines) == 0 {
			return "未采集到网络连接信息"
		}
		listen := 0
		established := 0
		for _, line := range lines {
			upper := strings.ToUpper(line)
			if strings.Contains(upper, "LISTEN") {
				listen++
			}
			if strings.Contains(upper, "ESTABLISHED") {
				established++
			}
		}
		return fmt.Sprintf("采集到 %d 条连接信息，其中监听 %d 条、已建立 %d 条", len(lines), listen, established)
	case "16":
		if len(lines) == 0 {
			return "未配置 FTP Banner"
		}
		return "已配置 FTP Banner"
	case "17":
		if len(lines) == 0 {
			return "未配置 FTP chroot 规则"
		}
		return fmt.Sprintf("已配置 %d 条 FTP chroot 规则", len(lines))
	case "18", "22":
		if len(lines) == 0 {
			return ""
		}
		return lines[0]
	case "19":
		if len(lines) == 0 {
			return "未配置 FTP Banner 文件"
		}
		return "已配置 FTP Banner 文件"
	case "20":
		if len(lines) == 0 {
			return "未配置 FTP 访问控制规则"
		}
		return fmt.Sprintf("已配置 %d 条 FTP 访问控制规则", len(lines))
	default:
		if len(lines) == 0 {
			return ""
		}
		if len(lines) == 1 {
			return lines[0]
		}
		return fmt.Sprintf("采集到 %d 条配置/日志内容", len(lines))
	}
}

func collectUnixReleaseInfo(template Template) (string, error) {
	switch template {
	case TemplateEulerOS:
		return readFileIfExists("/etc/euleros-release", false, 20)
	case TemplateKylin:
		return readFileIfExists("/etc/kylin-release", false, 20)
	default:
		value, err := readDescriptionFromOSRelease("/etc/os-release")
		if err == nil && strings.TrimSpace(value) != "" {
			return value, nil
		}
		return readFileIfExists("/etc/SuSE-release", false, 20)
	}
}

func readDescriptionFromOSRelease(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PRETTY_NAME=") && !strings.HasPrefix(line, "NAME=") && !strings.HasPrefix(line, "DESCRIPTION=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		return strings.Trim(parts[1], `"`), nil
	}
	return "", nil
}

func readFirstExistingFile(paths []string, stripComments bool, limit int) (string, error) {
	for _, path := range paths {
		value, err := readFileIfExists(path, stripComments, limit)
		if err == nil && strings.TrimSpace(value) != "" {
			return value, nil
		}
	}
	return "", nil
}

func readFileIfExists(path string, stripComments bool, limit int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	lines := make([]string, 0, limit)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if stripComments && strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

func parseKeyValueFromFiles(paths []string, key string) (string, error) {
	for _, path := range paths {
		value, err := readFileIfExists(path, true, 120)
		if err != nil {
			return "", err
		}
		for _, line := range nonEmptyLines(value) {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			if strings.TrimSpace(parts[0]) == key {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	return "", nil
}

func filterLinesContaining(path string, needles []string, limit int) (string, error) {
	value, err := readFileIfExists(path, true, 400)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, limit)
	for _, line := range nonEmptyLines(value) {
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				lines = append(lines, line)
				break
			}
		}
		if limit > 0 && len(lines) >= limit {
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

func readLastOutput(failed bool) (string, error) {
	command := "last -100 2>/dev/null"
	if failed {
		command = "lastb -100 2>/dev/null"
	}
	return executeNativeCheckCommand(context.Background(), TemplateLinux, nativeCheck{shell: "sh", command: command, limitNonEmptyLines: 120})
}

func readNetstatOutput() (string, error) {
	return executeNativeCheckCommand(context.Background(), TemplateLinux, nativeCheck{shell: "sh", command: "netstat -anp 2>/dev/null | head -300", limitNonEmptyLines: 300})
}
