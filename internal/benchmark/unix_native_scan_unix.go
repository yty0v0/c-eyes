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

func scanUnixNativeBenchmark(ctx context.Context, template Template, level BaselineLevel, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	if template == TemplateWindows {
		return ScanResult{}, false, nil
	}

	ruleSet, err := loadBenchmarkRuleSet(template, level)
	if err != nil {
		return ScanResult{}, true, err
	}
	ruleIndex := buildBenchmarkRuleIndex(ruleSet)

	profile, err := nativeProfileForTemplateLevel(template, level)
	if err != nil {
		return ScanResult{}, true, err
	}

	state := &unixBenchmarkCollectorState{}
	results := make([]benchmarkCheckResult, 0, len(profile.checks))
	for idx, check := range profile.checks {
		select {
		case <-ctx.Done():
			return ScanResult{}, true, ctx.Err()
		default:
		}

		notifyProgress(progress, benchmarkRangedProgress(benchmarkProgressExecuteStart, benchmarkProgressExecuteEnd, idx+1, len(profile.checks)), benchmarkProgressTotalSteps, "execute checks")

		result, handledDirect, directErr := collectUnixNativeCheck(ctx, template, check.id, state)
		runErr := directErr
		if handledDirect {
			if result.Eval == nil {
				result.Eval = map[string]any{}
			}
			result.Command = benchmarkCollectorCommand(template, check.id, "")
			if result.SectionType == "" {
				result.SectionType = "display"
			}
			result.Actual = normalizeTrim(result.Actual)
			result.Evidence = normalizeTrim(result.Evidence)
			if _, ok := result.Eval["actual"]; !ok {
				result.Eval["actual"] = result.Actual
			}
		} else {
			return ScanResult{}, true, fmt.Errorf("native unix benchmark collector missing direct mapping for template=%s check=%s", template, check.id)
		}
		result = shapeUnixBenchmarkResult(template, result)
		result = shapeUnixAdvancedResult(result)
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
			TemplateName:    benchmarkTemplateDisplayName(template, level),
			BaselineLevel:   string(level),
			TemplateVersion: "V6.0R03F02.0007",
			Industry:        "等级保护2.0",
			SystemVersion:   "V6.0R03F03SP07",
			Hash:            "42F1-91D7-00CD-EE46",
		},
		Summary: summarize(rows),
		Rows:    rows,
	}, true, nil
}

func benchmarkTemplateDisplayName(template Template, level BaselineLevel) string {
	if level == "" {
		level = BaselineLevel1
	}
	suffix := "_S1A" + string(level) + "G" + string(level)
	switch template {
	case TemplateLinux:
		return "Linux Benchmark" + suffix
	case TemplateEulerOS:
		return "EulerOS Benchmark" + suffix
	case TemplateKylin:
		return "Kylin Benchmark" + suffix
	case TemplateWindows:
		return "Windows Benchmark" + suffix
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
	result.Actual = fmt.Sprintf("采集到 %d 个本地账户，root 账户存在=%t", len(names), rootPresent)
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
	result.Actual = fmt.Sprintf("采集到 %d 个本地用户组，高权限组存在=%t", len(names), privileged)
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
	result.Actual = fmt.Sprintf("检测到 %d 个运行中的进程", len(names))
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
	result.Actual = fmt.Sprintf("检测到 %d 个服务，其中 %d 个为自动启用", len(names), autoEnabled)
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
	result.Actual = fmt.Sprintf("检测到 %d 个网络接口、%d 个地址", len(names), addressCount)
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
	result.Actual = fmt.Sprintf("检测到 %d 个文件系统，最高使用率 %d%%", len(names), highestUsed)
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
	result.Actual = fmt.Sprintf("检测到 %d 条 shadow 记录，%d 条弱口令或空口令标记", entryCount, emptyPasswordCount)
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
		case "9":
			value, err := filterLinesContaining("/etc/ssh/sshd_config", []string{"AllowUsers", "DenyUsers"}, 120)
			return configResult(checkID, value, err)
		case "18":
			value, err := collectUnixReleaseInfo(template)
			return configResult(checkID, value, err)
		}
	case TemplateKylin:
		switch checkID {
		case "8":
			value, err := collectUnixReleaseInfo(template)
			return configResult(checkID, value, err)
		case "13":
			value, err := readFirstExistingFile([]string{"/var/log/syslog", "/var/log/messages"}, false, 20)
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
	case "5":
		ptsRuleAbsent := len(lines) > 0
		for _, line := range lines {
			lower := strings.ToLower(strings.TrimSpace(line))
			if strings.Contains(lower, "pts") {
				ptsRuleAbsent = false
				break
			}
		}
		eval["pts_rule_absent"] = ptsRuleAbsent
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
		eval["log_target_count"] = len(lines)
		eval["access_control_present"] = len(lines) > 0
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
	case "16":
		eval["banner_configured"] = len(lines) > 0
	case "19":
		eval["banner_content_present"] = len(lines) > 0
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
		return fmt.Sprintf("采集到 %d 行日志摘要", len(lines))
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
		return fmt.Sprintf("采集到 %d 条连接，其中监听 %d 条、已建立 %d 条", len(lines), listen, established)
	case "16":
		if len(lines) == 0 {
			return "未配置 FTP Banner"
		}
		return "FTP Banner 已配置"
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
		return "FTP Banner 文件已配置"
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
		return fmt.Sprintf("采集到 %d 行配置内容", len(lines))
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

func shapeUnixAdvancedResult(result benchmarkCheckResult) benchmarkCheckResult {
	if result.Eval == nil {
		return result
	}
	switch result.ID {
	case "LNX-NET-ADV-001", "LNX-NET-ADV-002", "LNX-NET-ADV-003", "LNX-NET-ADV-004", "LNX-NET-ADV-005":
		if value, ok := parseFirstIntLine(nonEmptyLines(result.Evidence)); ok {
			result.Actual = fmt.Sprintf("内核/网络参数值 %d", value)
			result.Eval["int_value"] = value
			result.Eval["value"] = strconv.FormatInt(value, 10)
		}
	case "LNX-SVC-ADV-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 个高风险服务迹象", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "LNX-SVC-ADV-002":
		if value, ok := parseFirstIntLine(nonEmptyLines(result.Evidence)); ok {
			result.Actual = fmt.Sprintf("NFS 进程数 %d", value)
			result.Eval["int_value"] = value
			result.Eval["value"] = strconv.FormatInt(value, 10)
		}
	case "LNX-SSH-ADV-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 条 AllowUsers 规则", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "LNX-SSH-ADV-002":
		ok := strings.Contains(strings.ToLower(result.Evidence), "check result:true")
		result.Actual = "已检测 SSH Banner 合规状态"
		result.Eval["banner_ok"] = ok
	case "LNX-TRUST-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 个 trust 文件", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "LNX-TIME-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 条时间服务器规则", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "LNX-TIME-002":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 个时间同步守护进程", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "EUL-NET-ADV-001", "EUL-NET-ADV-002", "EUL-NET-ADV-003", "EUL-NET-ADV-004", "EUL-NET-ADV-005",
		"KYL-NET-ADV-001", "KYL-NET-ADV-002", "KYL-NET-ADV-003", "KYL-NET-ADV-004", "KYL-NET-ADV-005", "KYL-NET-ADV-006":
		if value, ok := parseFirstIntLine(nonEmptyLines(result.Evidence)); ok {
			result.Actual = fmt.Sprintf("内核/网络参数值 %d", value)
			result.Eval["int_value"] = value
			result.Eval["value"] = strconv.FormatInt(value, 10)
		}
	case "EUL-SSH-ADV-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 条 SSH Banner 规则", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
		result.Eval["banner_ok"] = count > 0
	case "KYL-SSH-ADV-001":
		ok := strings.Contains(strings.ToLower(result.Evidence), "check result:true")
		result.Actual = "已检测 SSH Banner/访问控制合规状态"
		result.Eval["banner_ok"] = ok
	case "EUL-TIME-001", "KYL-TIME-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 条时间服务器规则", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "EUL-TIME-002", "EUL-TIME-003":
		running := strings.Contains(strings.ToLower(result.Evidence), "active: active (running)") || strings.Contains(strings.ToLower(result.Evidence), "active (running)")
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 行时间同步状态信息", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
		result.Eval["daemon_running"] = running
	case "KYL-TIME-002":
		running := strings.Contains(strings.ToLower(result.Evidence), "ntp:start")
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 行时间同步状态信息", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
		result.Eval["daemon_running"] = running
	case "EUL-LOG-ADV-001", "EUL-LOG-ADV-002", "EUL-LOG-ADV-003", "KYL-LOG-ADV-001", "KYL-LOG-ADV-002", "KYL-LOG-ADV-003":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 条高级日志规则", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "EUL-HIST-001", "EUL-HIST-002", "KYL-HIST-001", "KYL-HIST-002":
		if value, ok := parseFirstIntLine(nonEmptyLines(result.Evidence)); ok {
			result.Actual = fmt.Sprintf("历史记录配置值 %d", value)
			result.Eval["int_value"] = value
			result.Eval["value"] = strconv.FormatInt(value, 10)
		}
	case "KYL-TRUST-001":
		count := len(nonEmptyLines(result.Evidence))
		result.Actual = fmt.Sprintf("检测到 %d 个 trust 文件", count)
		result.Eval["entry_count"] = count
		result.Eval["present"] = count > 0
	case "KYL-FS-ADV-001":
		lines := nonEmptyLines(result.Evidence)
		result.Actual = fmt.Sprintf("采集到 %d 行文件系统信息", len(lines))
		result.Eval["entry_count"] = len(lines)
		result.Eval["present"] = len(lines) > 0
	}
	return result
}

func parseFirstIntLine(lines []string) (int64, bool) {
	for _, line := range lines {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		if idx := strings.LastIndex(text, ":"); idx >= 0 {
			text = strings.TrimSpace(text[idx+1:])
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err == nil {
			return n, true
		}
	}
	return 0, false
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
