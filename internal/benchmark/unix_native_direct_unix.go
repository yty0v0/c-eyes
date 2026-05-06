//go:build !windows

package benchmark

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"edrsystem/internal/accountscan"
	"edrsystem/internal/processscan"
	"edrsystem/internal/startupscan"
	"edrsystem/internal/usergroupscan"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

type unixBenchmarkCollectorState struct {
	accountsLoaded    bool
	accounts          []accountscan.AccountInfo
	groupsLoaded      bool
	groups            []usergroupscan.UserGroupInfo
	processesLoaded   bool
	processes         []processscan.ProcessInfo
	startupsLoaded    bool
	startups          []startupscan.StartupInfo
	interfacesLoaded  bool
	interfaces        []unixInterfaceRecord
	disksLoaded       bool
	disks             []unixFilesystemRecord
	sensitiveLoaded   bool
	sensitive         []unixSensitiveFileRecord
	connectionsLoaded bool
	connections       []unixNetConnectionRecord
}

type unixNetConnectionRecord struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
}

type unixExitStatus struct {
	Termination int16
	Exit        int16
}

type unixUtmpTime struct {
	Sec  int32
	Usec int32
}

type unixUtmpRecord struct {
	Type     int16
	Pad      [2]byte
	PID      int32
	Line     [32]byte
	ID       [4]byte
	User     [32]byte
	Host     [256]byte
	Exit     unixExitStatus
	Session  int32
	Time     unixUtmpTime
	AddrV6   [4]int32
	Reserved [20]byte
}

type unixFailedLoginEntry struct {
	Name       string    `json:"name,omitempty"`
	Time       time.Time `json:"time"`
	TTY        string    `json:"tty,omitempty"`
	Host       string    `json:"host,omitempty"`
	PID        int32     `json:"pid,omitempty"`
	RecordType int16     `json:"record_type,omitempty"`
}

func collectUnixNativeCheck(ctx context.Context, template Template, checkID string, state *unixBenchmarkCollectorState) (benchmarkCheckResult, bool, error) {
	switch template {
	case TemplateLinux:
		return collectLinuxNativeCheck(ctx, checkID, state)
	case TemplateEulerOS:
		return collectEulerNativeCheck(ctx, checkID, state)
	case TemplateKylin:
		return collectKylinNativeCheck(ctx, checkID, state)
	default:
		return benchmarkCheckResult{}, false, nil
	}
}

func collectLinuxNativeCheck(ctx context.Context, checkID string, state *unixBenchmarkCollectorState) (benchmarkCheckResult, bool, error) {
	switch checkID {
	case "0":
		return collectUnixKernelCheckResult(), true, nil
	case "1":
		rows, err := ensureUnixAccounts(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixAccountsResult(newUnixResult(checkID), rows), true, nil
	case "2":
		rows, err := ensureUnixGroups(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixGroupsResult(newUnixResult(checkID), rows), true, nil
	case "3":
		return collectUnixShadowCheckResult(checkID)
	case "4":
		rows, err := ensureUnixSensitiveFiles(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixSensitiveFilesResult(newUnixResult(checkID), rows), true, nil
	case "5":
		return collectUnixConfigSummaryDirect(TemplateLinux, checkID)
	case "6":
		rows, err := ensureUnixServices(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixServicesResult(newUnixResult(checkID), rows), true, nil
	case "7":
		rows, err := ensureUnixInterfaces(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixInterfacesResult(newUnixResult(checkID), rows), true, nil
	case "8":
		rows, err := ensureUnixAccounts(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixLoginHistoryCheckResult(checkID, rows), true, nil
	case "11":
		result, err := collectUnixFailedLoginHistoryCheckResult(checkID)
		return result, true, err
	case "9", "12", "16", "17", "19", "20", "22":
		return collectUnixConfigSummaryDirect(TemplateLinux, checkID)
	case "21":
		return collectUnixPackageInventoryCheckResult(checkID), true, nil
	case "10":
		rows, err := ensureUnixFilesystems(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixFilesystemsResult(newUnixResult(checkID), rows), true, nil
	case "13":
		return collectUnixCleanupCheckResult(checkID), true, nil
	case "14":
		rows, err := ensureUnixConnections(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixConnectionsResult(newUnixResult(checkID), rows), true, nil
	case "15":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixProcessesResult(newUnixResult(checkID), rows), true, nil
	case "LNX-NET-ADV-001":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/ip_forward"), true, nil
	case "LNX-NET-ADV-002":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"), true, nil
	case "LNX-NET-ADV-003":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_source_route"), true, nil
	case "LNX-NET-ADV-004":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/send_redirects"), true, nil
	case "LNX-NET-ADV-005":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_redirects"), true, nil
	case "LNX-SVC-ADV-001":
		rows, err := ensureUnixServices(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixHighRiskServiceCheckResult(checkID, rows), true, nil
	case "LNX-SVC-ADV-002":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixProcessCountCheckResult(checkID, rows, func(name string) bool {
			return strings.Contains(strings.ToLower(name), "nfs")
		}), true, nil
	case "LNX-SSH-ADV-001":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/ssh/sshd_config", 120, func(line string) bool {
			return strings.HasPrefix(strings.TrimSpace(line), "AllowUsers")
		}), true, nil
	case "LNX-SSH-ADV-002":
		rows, err := ensureUnixConnections(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixSSHBannerCheckResult(checkID, rows), true, nil
	case "LNX-TRUST-001":
		return collectUnixTrustFilesCheckResult(checkID), true, nil
	case "LNX-TIME-001":
		return collectUnixTimeConfigCheckResult(checkID), true, nil
	case "LNX-TIME-002":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixTimeDaemonCheckResult(checkID, rows), true, nil
	default:
		return benchmarkCheckResult{}, false, nil
	}
}

func collectEulerNativeCheck(ctx context.Context, checkID string, state *unixBenchmarkCollectorState) (benchmarkCheckResult, bool, error) {
	switch checkID {
	case "0":
		return collectUnixKernelCheckResult(), true, nil
	case "1":
		rows, err := ensureUnixAccounts(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixAccountsResult(newUnixResult(checkID), rows), true, nil
	case "2":
		rows, err := ensureUnixGroups(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixGroupsResult(newUnixResult(checkID), rows), true, nil
	case "3", "5", "9", "18":
		return collectUnixConfigSummaryDirect(TemplateEulerOS, checkID)
	case "8":
		rows, err := ensureUnixAccounts(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixLoginHistoryCheckResult(checkID, rows), true, nil
	case "11":
		result, err := collectUnixFailedLoginHistoryCheckResult(checkID)
		return result, true, err
	case "4":
		rows, err := ensureUnixServices(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixServicesResult(newUnixResult(checkID), rows), true, nil
	case "6":
		rows, err := ensureUnixInterfaces(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixInterfacesResult(newUnixResult(checkID), rows), true, nil
	case "7":
		return collectUnixCleanupCheckResult(checkID), true, nil
	case "10":
		rows, err := ensureUnixFilesystems(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixFilesystemsResult(newUnixResult(checkID), rows), true, nil
	case "21":
		return collectUnixPackageInventoryCheckResult(checkID), true, nil
	case "14":
		rows, err := ensureUnixConnections(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixConnectionsResult(newUnixResult(checkID), rows), true, nil
	case "EUL-NET-ADV-001":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/ip_forward"), true, nil
	case "EUL-NET-ADV-002":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_source_route"), true, nil
	case "EUL-NET-ADV-003":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/send_redirects"), true, nil
	case "EUL-NET-ADV-004":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"), true, nil
	case "EUL-NET-ADV-005":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_redirects"), true, nil
	case "EUL-SSH-ADV-001":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/ssh/sshd_config", 120, func(line string) bool {
			return strings.Contains(line, "Banner")
		}), true, nil
	case "EUL-LOG-ADV-001":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "*.info;mail.none;authpriv.none;cron.none")
		}), true, nil
	case "EUL-LOG-ADV-002":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "authpriv.*")
		}), true, nil
	case "EUL-LOG-ADV-003":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "cron.*") && strings.Contains(line, "/var/log/cron")
		}), true, nil
	case "EUL-TIME-001":
		return collectUnixTimeConfigCheckResult(checkID), true, nil
	case "EUL-TIME-002":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixSingleDaemonStatusCheckResult(checkID, rows, "chronyd"), true, nil
	case "EUL-TIME-003":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixSingleDaemonStatusCheckResult(checkID, rows, "ntpd"), true, nil
	case "EUL-HIST-001":
		return collectUnixEnvValueCheckResult(checkID, "HISTSIZE"), true, nil
	case "EUL-HIST-002":
		return collectUnixEnvValueCheckResult(checkID, "HISTFILESIZE"), true, nil
	default:
		return benchmarkCheckResult{}, false, nil
	}
}

func collectKylinNativeCheck(ctx context.Context, checkID string, state *unixBenchmarkCollectorState) (benchmarkCheckResult, bool, error) {
	switch checkID {
	case "1":
		rows, err := ensureUnixServices(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixServicesResult(newUnixResult(checkID), rows), true, nil
	case "2":
		return collectUnixCleanupCheckResult(checkID), true, nil
	case "3":
		rows, err := ensureUnixSensitiveFiles(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixSensitiveFilesResult(newUnixResult(checkID), rows), true, nil
	case "4":
		return collectUnixShadowCheckResult(checkID)
	case "5":
		result, err := collectUnixFailedLoginHistoryCheckResult(checkID)
		return result, true, err
	case "6":
		rows, err := ensureUnixGroups(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixGroupsResult(newUnixResult(checkID), rows), true, nil
	case "7":
		return collectUnixKernelCheckResult(), true, nil
	case "8", "13":
		return collectUnixConfigSummaryDirect(TemplateKylin, checkID)
	case "9":
		return collectUnixPackageInventoryCheckResult(checkID), true, nil
	case "10":
		rows, err := ensureUnixFilesystems(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixFilesystemsResult(newUnixResult(checkID), rows), true, nil
	case "11":
		rows, err := ensureUnixInterfaces(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixInterfacesResult(newUnixResult(checkID), rows), true, nil
	case "12":
		rows, err := ensureUnixAccounts(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixLoginHistoryCheckResult(checkID, rows), true, nil
	case "14":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixProcessesResult(newUnixResult(checkID), rows), true, nil
	case "15":
		rows, err := ensureUnixConnections(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return shapeUnixConnectionsResult(newUnixResult(checkID), rows), true, nil
	case "KYL-TRUST-001":
		return collectUnixTrustFilesCheckResult(checkID), true, nil
	case "KYL-LOG-ADV-001":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "*.info") && strings.Contains(line, "/var/log/messages")
		}), true, nil
	case "KYL-FS-ADV-001":
		rows, err := ensureUnixFilesystems(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return benchmarkCheckResult{
			ID:          checkID,
			SectionType: "auto",
			Actual:      fmt.Sprintf("collected %d filesystem records", len(rows)),
			Evidence:    mustMarshalPrettyJSON(rows),
			Eval: map[string]any{
				"entry_count": len(rows),
				"present":     len(rows) > 0,
			},
		}, true, nil
	case "KYL-NET-ADV-001":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/ip_forward"), true, nil
	case "KYL-NET-ADV-002":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/send_redirects"), true, nil
	case "KYL-NET-ADV-003":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_source_route"), true, nil
	case "KYL-NET-ADV-004":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts"), true, nil
	case "KYL-NET-ADV-005":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/ip_forward"), true, nil
	case "KYL-NET-ADV-006":
		return collectUnixProcSysCheckResult(checkID, "/proc/sys/net/ipv4/conf/all/accept_redirects"), true, nil
	case "KYL-TIME-001":
		return collectUnixTimeConfigCheckResult(checkID), true, nil
	case "KYL-TIME-002":
		rows, err := ensureUnixProcesses(ctx, state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixTimeDaemonCheckResult(checkID, rows), true, nil
	case "KYL-SSH-ADV-001":
		rows, err := ensureUnixConnections(state)
		if err != nil {
			return benchmarkCheckResult{}, false, err
		}
		return collectUnixSSHBannerCheckResult(checkID, rows), true, nil
	case "KYL-LOG-ADV-002":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "authpriv.*") && strings.Contains(line, "/var/log/secure")
		}), true, nil
	case "KYL-LOG-ADV-003":
		return collectUnixFilteredFileCheckResult(checkID, "/etc/rsyslog.conf", 120, func(line string) bool {
			return strings.Contains(line, "@")
		}), true, nil
	case "KYL-HIST-001":
		return collectUnixEnvValueCheckResult(checkID, "HISTSIZE"), true, nil
	case "KYL-HIST-002":
		return collectUnixEnvValueCheckResult(checkID, "HISTFILESIZE"), true, nil
	default:
		return benchmarkCheckResult{}, false, nil
	}
}

func newUnixResult(id string) benchmarkCheckResult {
	return benchmarkCheckResult{
		ID:          id,
		SectionType: "display",
		Eval:        map[string]any{},
	}
}

func collectUnixKernelCheckResult() benchmarkCheckResult {
	value, _ := readFileIfExists("/proc/version", false, 1)
	value = normalizeTrim(value)
	return benchmarkCheckResult{
		Actual:   value,
		Evidence: value,
		Eval: map[string]any{
			"present": strings.TrimSpace(value) != "",
		},
	}
}

func collectUnixShadowCheckResult(checkID string) (benchmarkCheckResult, bool, error) {
	value, err := readFileIfExists("/etc/shadow", false, 300)
	if err != nil {
		return benchmarkCheckResult{}, false, err
	}
	result := newUnixResult(checkID)
	result.Actual = normalizeTrim(value)
	result.Evidence = normalizeTrim(value)
	result = shapeUnixShadowSummary(result)
	return result, true, nil
}

func collectUnixCleanupCheckResult(checkID string) benchmarkCheckResult {
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "display",
		Actual:      "无需清理临时工件",
		Evidence:    "无需清理临时工件",
		Eval: map[string]any{
			"present": true,
		},
	}
}

func collectUnixConfigSummaryDirect(template Template, checkID string) (benchmarkCheckResult, bool, error) {
	value, err := collectUnixConfigSummary(template, checkID)
	if err != nil {
		return benchmarkCheckResult{}, false, err
	}
	if value.Eval == nil {
		value.Eval = map[string]any{}
	}
	return value, true, nil
}

func collectUnixProcSysCheckResult(checkID, path string) benchmarkCheckResult {
	value, _ := readFileIfExists(path, false, 1)
	value = normalizeTrim(value)
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      value,
		Evidence:    value,
		Eval: map[string]any{
			"present": strings.TrimSpace(value) != "",
		},
	}
}

func collectUnixFilteredFileCheckResult(checkID, path string, limit int, predicate func(line string) bool) benchmarkCheckResult {
	value, _ := readFileIfExists(path, true, 400)
	lines := make([]string, 0, limit)
	for _, line := range nonEmptyLines(value) {
		if predicate(line) {
			lines = append(lines, line)
			if limit > 0 && len(lines) >= limit {
				break
			}
		}
	}
	evidence := strings.Join(lines, "\n")
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      evidence,
		Evidence:    evidence,
		Eval: map[string]any{
			"present": len(lines) > 0,
		},
	}
}

func collectUnixTrustFilesCheckResult(checkID string) benchmarkCheckResult {
	paths := findUnixTrustFiles("/", 3)
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      strings.Join(paths, "\n"),
		Evidence:    strings.Join(paths, "\n"),
		Eval: map[string]any{
			"present": len(paths) > 0,
		},
	}
}

func collectUnixTimeConfigCheckResult(checkID string) benchmarkCheckResult {
	lines := collectUnixTimeConfigLines()
	evidence := strings.Join(lines, "\n")
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      evidence,
		Evidence:    evidence,
		Eval: map[string]any{
			"present": len(lines) > 0,
		},
	}
}

func collectUnixTimeDaemonCheckResult(checkID string, rows []processscan.ProcessInfo) benchmarkCheckResult {
	lines := make([]string, 0, 2)
	if unixProcessNameExists(rows, "ntpd") || unixProcessNameExists(rows, "ntp") {
		lines = append(lines, "ntp:start")
	}
	if unixProcessNameExists(rows, "chronyd") {
		lines = append(lines, "chronyd:start")
	}
	evidence := strings.Join(lines, "\n")
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      evidence,
		Evidence:    evidence,
		Eval: map[string]any{
			"present": len(lines) > 0,
		},
	}
}

func collectUnixLoginHistoryCheckResult(checkID string, rows []accountscan.AccountInfo) benchmarkCheckResult {
	type loginEntry struct {
		Name          string    `json:"name"`
		LastLoginTime time.Time `json:"last_login_time"`
		TTY           string    `json:"tty,omitempty"`
		IP            string    `json:"ip,omitempty"`
	}

	entries := make([]loginEntry, 0, len(rows))
	for _, row := range rows {
		if row.LastLoginTime == nil || row.Name == nil || strings.TrimSpace(*row.Name) == "" {
			continue
		}
		entries = append(entries, loginEntry{
			Name:          strings.TrimSpace(*row.Name),
			LastLoginTime: row.LastLoginTime.UTC(),
			TTY:           derefString(row.LastLoginTTY),
			IP:            derefString(row.LastLoginIP),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].LastLoginTime.After(entries[j].LastLoginTime)
	})
	evidenceEntries := entries
	if len(evidenceEntries) > 100 {
		evidenceEntries = evidenceEntries[:100]
	}
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "display",
		Actual:      fmt.Sprintf("collected %d recent login records", len(entries)),
		Evidence:    mustMarshalPrettyJSON(evidenceEntries),
		Eval: map[string]any{
			"present":     len(entries) > 0,
			"entry_count": len(entries),
		},
	}
}

func collectUnixFailedLoginHistoryCheckResult(checkID string) (benchmarkCheckResult, error) {
	entries, err := readUnixFailedLoginEntries("/var/log/btmp")
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	evidenceEntries := entries
	if len(evidenceEntries) > 100 {
		evidenceEntries = evidenceEntries[:100]
	}

	actual := fmt.Sprintf("collected %d recent failed login records", len(entries))
	if len(entries) == 0 {
		actual = "no recent failed login records collected"
	}

	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "display",
		Actual:      actual,
		Evidence:    mustMarshalPrettyJSON(evidenceEntries),
		Eval: map[string]any{
			"present":     len(entries) > 0,
			"entry_count": len(entries),
		},
	}, nil
}

func readUnixFailedLoginEntries(path string) ([]unixFailedLoginEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	recordSize := binary.Size(unixUtmpRecord{})
	if recordSize <= 0 || len(data) < recordSize {
		return nil, nil
	}

	reader := bytes.NewReader(data)
	entries := make([]unixFailedLoginEntry, 0, len(data)/recordSize)
	for reader.Len() >= recordSize {
		var record unixUtmpRecord
		if err := binary.Read(reader, binary.LittleEndian, &record); err != nil {
			return nil, err
		}
		entry, ok := unixFailedLoginEntryFromRecord(record)
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Time.After(entries[j].Time)
	})
	return entries, nil
}

func unixFailedLoginEntryFromRecord(record unixUtmpRecord) (unixFailedLoginEntry, bool) {
	timestamp := time.Unix(int64(record.Time.Sec), int64(record.Time.Usec)*1000).UTC()
	if record.Time.Sec <= 0 {
		return unixFailedLoginEntry{}, false
	}

	name := unixTrimCString(record.User[:])
	line := unixTrimCString(record.Line[:])
	host := unixTrimCString(record.Host[:])
	if name == "" && line == "" && host == "" {
		return unixFailedLoginEntry{}, false
	}

	return unixFailedLoginEntry{
		Name:       name,
		Time:       timestamp,
		TTY:        line,
		Host:       host,
		PID:        record.PID,
		RecordType: record.Type,
	}, true
}

func unixTrimCString(value []byte) string {
	if idx := bytes.IndexByte(value, 0); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(string(value))
}

func collectUnixSingleDaemonStatusCheckResult(checkID string, rows []processscan.ProcessInfo, processName string) benchmarkCheckResult {
	status := ""
	if unixProcessNameExists(rows, processName) {
		status = "Active: active (running)"
	}
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      status,
		Evidence:    status,
		Eval: map[string]any{
			"present": status != "",
		},
	}
}

func collectUnixEnvValueCheckResult(checkID, key string) benchmarkCheckResult {
	value := strings.TrimSpace(os.Getenv(key))
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      value,
		Evidence:    value,
		Eval: map[string]any{
			"present": value != "",
		},
	}
}

func collectUnixPackageInventoryCheckResult(checkID string) benchmarkCheckResult {
	packages := collectUnixPackages()
	actual := fmt.Sprintf("collected %d installed package summaries", len(packages))
	if len(packages) == 0 {
		actual = "未采集到已安装软件包摘要"
	}
	evidenceRows := packages
	if len(evidenceRows) > 200 {
		evidenceRows = evidenceRows[:200]
	}
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "display",
		Actual:      actual,
		Evidence:    mustMarshalPrettyJSON(evidenceRows),
		Eval: map[string]any{
			"present":     len(packages) > 0,
			"entry_count": len(packages),
		},
	}
}

func collectUnixSSHBannerCheckResult(checkID string, rows []unixNetConnectionRecord) benchmarkCheckResult {
	sshListening := unixPortListening(rows, 22)
	_, motdErr := os.Stat("/etc/motd")
	motdExists := motdErr == nil
	value := "check result:true"
	if sshListening && !motdExists {
		value = "check result:false"
	}
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      value,
		Evidence:    value,
		Eval: map[string]any{
			"present": true,
		},
	}
}

func collectUnixHighRiskServiceCheckResult(checkID string, rows []startupscan.StartupInfo) benchmarkCheckResult {
	denyList := map[string]struct{}{
		"klogin": {}, "tftp": {}, "sendmail": {}, "echo": {}, "lpd": {}, "chargen": {},
		"printer": {}, "ntalk": {}, "ypbind": {}, "bootps": {}, "discard": {}, "kshell": {},
		"daytime": {}, "ident": {}, "time": {},
	}
	hits := make([]string, 0, 8)
	for _, row := range rows {
		name := strings.ToLower(strings.TrimSpace(firstNonEmpty(derefString(row.Name), derefString(row.ShowName))))
		if name == "" {
			continue
		}
		if _, ok := denyList[name]; ok {
			hits = append(hits, name)
		}
	}
	sort.Strings(hits)
	evidence := strings.Join(hits, "\n")
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      evidence,
		Evidence:    evidence,
		Eval: map[string]any{
			"present": len(hits) > 0,
		},
	}
}

func collectUnixProcessCountCheckResult(checkID string, rows []processscan.ProcessInfo, predicate func(name string) bool) benchmarkCheckResult {
	count := 0
	for _, row := range rows {
		name := strings.TrimSpace(derefString(row.Name))
		if name == "" {
			continue
		}
		if predicate(name) {
			count++
		}
	}
	text := strconv.Itoa(count)
	return benchmarkCheckResult{
		ID:          checkID,
		SectionType: "auto",
		Actual:      text,
		Evidence:    text,
		Eval: map[string]any{
			"present": true,
		},
	}
}

func ensureUnixAccounts(ctx context.Context, state *unixBenchmarkCollectorState) ([]accountscan.AccountInfo, error) {
	if state.accountsLoaded {
		return state.accounts, nil
	}
	scan, err := accountscan.Scan(ctx, accountscan.AccountScanParams{})
	if err != nil {
		return nil, err
	}
	state.accountsLoaded = true
	state.accounts = scan.Rows
	return state.accounts, nil
}

func ensureUnixGroups(ctx context.Context, state *unixBenchmarkCollectorState) ([]usergroupscan.UserGroupInfo, error) {
	if state.groupsLoaded {
		return state.groups, nil
	}
	scan, err := usergroupscan.Scan(ctx, usergroupscan.UserGroupScanParams{})
	if err != nil {
		return nil, err
	}
	state.groupsLoaded = true
	state.groups = scan.Rows
	return state.groups, nil
}

func ensureUnixProcesses(ctx context.Context, state *unixBenchmarkCollectorState) ([]processscan.ProcessInfo, error) {
	if state.processesLoaded {
		return state.processes, nil
	}
	rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
	if err != nil {
		return nil, err
	}
	state.processesLoaded = true
	state.processes = rows
	return state.processes, nil
}

func ensureUnixServices(ctx context.Context, state *unixBenchmarkCollectorState) ([]startupscan.StartupInfo, error) {
	if state.startupsLoaded {
		return state.startups, nil
	}
	scan, err := startupscan.Scan(ctx, startupscan.StartupScanParams{})
	if err != nil {
		return nil, err
	}
	state.startupsLoaded = true
	state.startups = scan.Rows
	return state.startups, nil
}

func ensureUnixInterfaces(state *unixBenchmarkCollectorState) ([]unixInterfaceRecord, error) {
	if state.interfacesLoaded {
		return state.interfaces, nil
	}
	rows, err := collectUnixInterfaces()
	if err != nil {
		return nil, err
	}
	state.interfacesLoaded = true
	state.interfaces = rows
	return state.interfaces, nil
}

func ensureUnixFilesystems(state *unixBenchmarkCollectorState) ([]unixFilesystemRecord, error) {
	if state.disksLoaded {
		return state.disks, nil
	}
	rows, err := collectUnixFilesystems()
	if err != nil {
		return nil, err
	}
	state.disksLoaded = true
	state.disks = rows
	return state.disks, nil
}

func ensureUnixSensitiveFiles(state *unixBenchmarkCollectorState) ([]unixSensitiveFileRecord, error) {
	if state.sensitiveLoaded {
		return state.sensitive, nil
	}
	state.sensitiveLoaded = true
	state.sensitive = collectUnixSensitiveFiles([]string{"/etc/shadow", "/etc/gshadow", "/etc/passwd"})
	return state.sensitive, nil
}

func ensureUnixConnections(state *unixBenchmarkCollectorState) ([]unixNetConnectionRecord, error) {
	if state.connectionsLoaded {
		return state.connections, nil
	}
	rows, err := collectUnixNetConnections()
	if err != nil {
		return nil, err
	}
	state.connectionsLoaded = true
	state.connections = rows
	return state.connections, nil
}

func shapeUnixConnectionsResult(result benchmarkCheckResult, rows []unixNetConnectionRecord) benchmarkCheckResult {
	listen := 0
	established := 0
	for _, row := range rows {
		switch strings.ToUpper(strings.TrimSpace(row.State)) {
		case "LISTEN":
			listen++
		case "ESTABLISHED":
			established++
		}
	}
	result.Actual = fmt.Sprintf("collected %d connections, including %d listening and %d established", len(rows), listen, established)
	result.Evidence = mustMarshalPrettyJSON(rows)
	result.Eval["present"] = len(rows) > 0
	result.Eval["entry_count"] = len(rows)
	result.Eval["listen_count"] = listen
	result.Eval["established_count"] = established
	return result
}

func collectUnixNetConnections() ([]unixNetConnectionRecord, error) {
	rows := make([]unixNetConnectionRecord, 0, 256)
	collect := func(path, protocol string) error {
		parsed, err := parseUnixProcNetFile(path, protocol)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rows = append(rows, parsed...)
		return nil
	}
	if err := collect("/proc/net/tcp", "tcp"); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/tcp6", "tcp6"); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/udp", "udp"); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/udp6", "udp6"); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Protocol != rows[j].Protocol {
			return rows[i].Protocol < rows[j].Protocol
		}
		if rows[i].LocalAddress != rows[j].LocalAddress {
			return rows[i].LocalAddress < rows[j].LocalAddress
		}
		if rows[i].LocalPort != rows[j].LocalPort {
			return rows[i].LocalPort < rows[j].LocalPort
		}
		if rows[i].RemoteAddress != rows[j].RemoteAddress {
			return rows[i].RemoteAddress < rows[j].RemoteAddress
		}
		return rows[i].RemotePort < rows[j].RemotePort
	})
	return rows, nil
}

func parseUnixProcNetFile(path, protocol string) ([]unixNetConnectionRecord, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) <= 1 {
		return nil, nil
	}
	out := make([]unixNetConnectionRecord, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		localAddr, localPort, err := parseUnixProcHexAddress(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseUnixProcHexAddress(fields[2])
		if err != nil {
			continue
		}
		out = append(out, unixNetConnectionRecord{
			Protocol:      protocol,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         unixTCPStateName(fields[3]),
		})
	}
	return out, nil
}

func parseUnixProcHexAddress(value string) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address")
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	ip, err := parseUnixProcHexIP(parts[0])
	if err != nil {
		return "", 0, err
	}
	return ip, int(port64), nil
}

func parseUnixProcHexIP(hexIP string) (string, error) {
	switch len(hexIP) {
	case 8:
		raw, err := hex.DecodeString(hexIP)
		if err != nil || len(raw) != 4 {
			return "", fmt.Errorf("invalid ipv4 hex")
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), nil
	case 32:
		raw, err := hex.DecodeString(hexIP)
		if err != nil || len(raw) != 16 {
			return "", fmt.Errorf("invalid ipv6 hex")
		}
		normalized := make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			normalized[i] = raw[i+3]
			normalized[i+1] = raw[i+2]
			normalized[i+2] = raw[i+1]
			normalized[i+3] = raw[i]
		}
		return net.IP(normalized).String(), nil
	default:
		return "", fmt.Errorf("unsupported address size")
	}
}

func unixTCPStateName(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	case "03":
		return "SYN_RECV"
	case "04":
		return "FIN_WAIT1"
	case "05":
		return "FIN_WAIT2"
	case "06":
		return "TIME_WAIT"
	case "07":
		return "CLOSE"
	case "08":
		return "CLOSE_WAIT"
	case "09":
		return "LAST_ACK"
	case "0A":
		return "LISTEN"
	case "0B":
		return "CLOSING"
	default:
		return strings.ToUpper(strings.TrimSpace(value))
	}
}

func unixPortListening(rows []unixNetConnectionRecord, port int) bool {
	for _, row := range rows {
		if row.LocalPort == port && strings.EqualFold(strings.TrimSpace(row.State), "LISTEN") {
			return true
		}
	}
	return false
}

func unixProcessNameExists(rows []processscan.ProcessInfo, names ...string) bool {
	lookup := make(map[string]struct{}, len(names))
	for _, name := range names {
		lookup[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for _, row := range rows {
		current := strings.ToLower(strings.TrimSpace(derefString(row.Name)))
		if current == "" {
			continue
		}
		if _, ok := lookup[current]; ok {
			return true
		}
	}
	return false
}

func collectUnixTimeConfigLines() []string {
	type fileRule struct {
		path      string
		predicate func(line string) bool
	}
	rules := []fileRule{
		{
			path: "/etc/ntp.conf",
			predicate: func(line string) bool {
				return strings.Contains(line, "server") && !strings.Contains(line, "127.127.1.0") && !strings.Contains(line, "127.0.0.1")
			},
		},
		{
			path: "/etc/chrony.conf",
			predicate: func(line string) bool {
				return strings.Contains(line, "server") && !strings.Contains(line, "127.127.1.0") && !strings.Contains(line, "127.0.0.1")
			},
		},
	}
	lines := make([]string, 0, 8)
	for _, rule := range rules {
		value, _ := readFileIfExists(rule.path, true, 200)
		for _, line := range nonEmptyLines(value) {
			if rule.predicate(line) {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

func findUnixTrustFiles(root string, maxDepth int) []string {
	targets := map[string]struct{}{
		"hosts.equiv": {},
		".rhosts":     {},
		".netrc":      {},
	}
	results := make([]string, 0, 8)
	root = filepath.Clean(root)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		depth := 0
		for _, part := range strings.Split(rel, string(os.PathSeparator)) {
			if strings.TrimSpace(part) != "" {
				depth++
			}
		}
		if d.IsDir() && depth > maxDepth {
			return filepath.SkipDir
		}
		if depth > maxDepth {
			return nil
		}
		if _, ok := targets[d.Name()]; ok {
			results = append(results, path)
		}
		return nil
	})
	sort.Strings(results)
	return results
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

type unixPackageRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"`
}

func collectUnixPackages() []unixPackageRecord {
	if rows := collectUnixDpkgPackages(); len(rows) > 0 {
		return rows
	}
	return collectUnixRpmPackages()
}

func collectUnixDpkgPackages() []unixPackageRecord {
	file, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	defer file.Close()

	rows := make([]unixPackageRecord, 0, 256)
	scanner := bufio.NewScanner(file)
	var pkg, version string
	flush := func() {
		if strings.TrimSpace(pkg) == "" {
			pkg = ""
			version = ""
			return
		}
		rows = append(rows, unixPackageRecord{
			Name:    strings.TrimSpace(pkg),
			Version: strings.TrimSpace(version),
			Source:  "dpkg-status",
		})
		pkg = ""
		version = ""
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "Package:") {
			pkg = strings.TrimSpace(strings.TrimPrefix(line, "Package:"))
			continue
		}
		if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	flush()
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Name < rows[j].Name
	})
	return rows
}

func collectUnixRpmPackages() []unixPackageRecord {
	paths := []string{
		"/var/lib/rpm/Packages",
		"/usr/lib/sysimage/rpm/Packages",
		"/var/lib/rpm/rpmdb.sqlite",
		"/usr/lib/sysimage/rpm/rpmdb.sqlite",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		db, err := rpmdb.Open(path)
		if err != nil {
			continue
		}
		pkgs, err := db.ListPackages()
		_ = db.Close()
		if err != nil {
			continue
		}
		rows := mapUnixRpmPackages(pkgs)
		if len(rows) > 0 {
			sort.Slice(rows, func(i, j int) bool {
				return rows[i].Name < rows[j].Name
			})
			return rows
		}
	}
	return nil
}

func mapUnixRpmPackages(pkgs any) []unixPackageRecord {
	value := reflect.ValueOf(pkgs)
	if value.Kind() != reflect.Slice {
		return nil
	}
	rows := make([]unixPackageRecord, 0, value.Len())
	for i := 0; i < value.Len(); i++ {
		pkg := value.Index(i).Interface()
		name := benchmarkReflectStringField(pkg, "Name")
		if strings.TrimSpace(name) == "" {
			continue
		}
		version := benchmarkReflectStringField(pkg, "Version")
		release := benchmarkReflectStringField(pkg, "Release")
		if strings.TrimSpace(release) != "" {
			if strings.TrimSpace(version) != "" {
				version = strings.TrimSpace(version) + "-" + strings.TrimSpace(release)
			} else {
				version = strings.TrimSpace(release)
			}
		}
		rows = append(rows, unixPackageRecord{
			Name:    strings.TrimSpace(name),
			Version: strings.TrimSpace(version),
			Source:  "rpmdb",
		})
	}
	return rows
}

func benchmarkReflectStringField(value any, name string) string {
	current := reflect.ValueOf(value)
	if current.Kind() == reflect.Pointer {
		current = current.Elem()
	}
	if current.Kind() != reflect.Struct {
		return ""
	}
	field := current.FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		return ""
	}
	return field.String()
}
