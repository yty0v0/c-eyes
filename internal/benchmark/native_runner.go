package benchmark

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

type nativeCheck struct {
	id                 string
	command            string
	shell              string
	limitNonEmptyLines int
}

type nativeTemplateProfile struct {
	uuid         string
	templateTime string
	checks       []nativeCheck
}

func runNativeTemplateChecks(
	ctx context.Context,
	template Template,
	workingRoot string,
	progress func(done, total int, stage string),
) (string, error) {
	profile, err := nativeProfileForTemplate(template)
	if err != nil {
		return "", err
	}

	cmdInfo := time.Now().Format("06-01-02")
	items := make([]xmlItem, 0, len(profile.checks))
	for idx, check := range profile.checks {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		notifyProgress(progress, benchmarkRangedProgress(benchmarkProgressExecuteStart, benchmarkProgressExecuteEnd, idx+1, len(profile.checks)), benchmarkProgressTotalSteps, "execute checks")

		actual, runErr := executeNativeCheckCommand(ctx, template, check)
		actual = strings.TrimSpace(actual)
		if check.limitNonEmptyLines > 0 {
			actual = keepFirstNonEmptyLines(actual, check.limitNonEmptyLines)
		}
		if runErr != nil {
			if actual != "" {
				actual += "\n"
			}
			actual += fmt.Sprintf("failed to execute command: %v", runErr)
		}

		items = append(items, xmlItem{
			Flag: check.id,
			Cmd: xmlCmd{
				Info:    cmdInfo,
				Command: check.command,
				Value:   actual,
			},
		})
	}

	raw := baselineXML{
		UUID: profile.uuid,
		IP:   resolveHostIdentity(),
		Time: profile.templateTime,
		Security: []xmlSection{
			{
				Type:  "display",
				Items: items,
			},
		},
	}

	payload, err := xml.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal native benchmark xml failed: %w", err)
	}

	hostPart := sanitizeFileComponent(raw.IP)
	if hostPart == "" {
		hostPart = "unknown-host"
	}
	fileName := fmt.Sprintf("%s_%s_chk.xml", hostPart, profile.uuid)
	outPath := filepath.Join(workingRoot, fileName)

	data := append([]byte(xml.Header), payload...)
	data = append(data, '\n')
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write native benchmark xml failed: %w", err)
	}
	return outPath, nil
}

func executeNativeCheckCommand(ctx context.Context, template Template, check nativeCheck) (string, error) {
	command := strings.TrimSpace(check.command)
	if command == "" {
		return "", nil
	}

	shell := strings.ToLower(strings.TrimSpace(check.shell))
	if shell == "" {
		if template == TemplateWindows {
			shell = "cmd"
		} else {
			shell = "sh"
		}
	}

	if template != TemplateWindows && shell == "cmd" {
		shell = "sh"
	}

	commandToRun := command
	if template == TemplateWindows {
		switch shell {
		case "powershell":
			commandToRun = wrapPowerShellUTF8(command)
		case "cmd":
			commandToRun = wrapCmdUTF8(command)
		}
	}

	var cmd *exec.Cmd
	switch shell {
	case "powershell":
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", commandToRun)
	case "sh":
		cmd = exec.CommandContext(ctx, "sh", "-c", commandToRun)
	case "cmd":
		cmd = exec.CommandContext(ctx, "cmd", "/c", commandToRun)
	default:
		if template == TemplateWindows {
			cmd = exec.CommandContext(ctx, "cmd", "/c", commandToRun)
		} else {
			cmd = exec.CommandContext(ctx, "sh", "-c", commandToRun)
		}
	}

	output, err := cmd.CombinedOutput()
	return normalizeCommandOutput(template, output), err
}

func wrapPowerShellUTF8(command string) string {
	return "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding; " + command
}

func wrapCmdUTF8(command string) string {
	return "chcp 65001>nul && " + command
}

func normalizeCommandOutput(template Template, output []byte) string {
	if len(output) == 0 {
		return ""
	}

	if decoded, ok := decodeUTF16WithBOM(output); ok {
		return strings.TrimPrefix(decoded, "\ufeff")
	}
	if decoded, ok := decodeUTF16LEHeuristic(output); ok {
		return strings.TrimPrefix(decoded, "\ufeff")
	}
	if utf8.Valid(output) {
		return strings.TrimPrefix(string(output), "\ufeff")
	}

	if template == TemplateWindows {
		if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(output); err == nil && utf8.Valid(decoded) {
			return string(decoded)
		}
		if decoded, err := simplifiedchinese.GB18030.NewDecoder().Bytes(output); err == nil && utf8.Valid(decoded) {
			return string(decoded)
		}
	}

	return string(output)
}

func decodeUTF16WithBOM(output []byte) (string, bool) {
	if len(output) < 2 || len(output)%2 != 0 {
		return "", false
	}

	le := output[0] == 0xFF && output[1] == 0xFE
	be := output[0] == 0xFE && output[1] == 0xFF
	if !le && !be {
		return "", false
	}

	u16 := make([]uint16, 0, len(output)/2)
	for i := 0; i < len(output); i += 2 {
		var v uint16
		if le {
			v = binary.LittleEndian.Uint16(output[i : i+2])
		} else {
			v = binary.BigEndian.Uint16(output[i : i+2])
		}
		u16 = append(u16, v)
	}
	return string(runesFromUTF16(u16)), true
}

func decodeUTF16LEHeuristic(output []byte) (string, bool) {
	if len(output) < 4 || len(output)%2 != 0 {
		return "", false
	}

	zeroAtOdd := 0
	samples := 0
	for i := 1; i < len(output); i += 2 {
		samples++
		if output[i] == 0 {
			zeroAtOdd++
		}
	}
	// Common UTF-16LE ASCII-ish output pattern: lots of zero bytes at odd positions.
	if samples == 0 || zeroAtOdd*100/samples < 30 {
		return "", false
	}

	u16 := make([]uint16, 0, len(output)/2)
	for i := 0; i < len(output); i += 2 {
		u16 = append(u16, binary.LittleEndian.Uint16(output[i:i+2]))
	}
	return string(runesFromUTF16(u16)), true
}

func runesFromUTF16(values []uint16) []rune {
	if len(values) == 0 {
		return nil
	}
	runes := make([]rune, 0, len(values))
	for i := 0; i < len(values); i++ {
		v := values[i]
		if v >= 0xD800 && v <= 0xDBFF && i+1 < len(values) {
			low := values[i+1]
			if low >= 0xDC00 && low <= 0xDFFF {
				r := rune(v-0xD800)<<10 + rune(low-0xDC00) + 0x10000
				runes = append(runes, r)
				i++
				continue
			}
		}
		runes = append(runes, rune(v))
	}
	return runes
}

func keepFirstNonEmptyLines(text string, limit int) string {
	if limit <= 0 {
		return strings.TrimSpace(text)
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, limit)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
		if len(out) >= limit {
			break
		}
	}
	return strings.TrimSpace(strings.Join(out, "\n"))
}

func resolveHostIdentity() string {
	if ip := firstNonLoopbackIPv4(); ip != "" {
		return ip
	}
	if host, err := os.Hostname(); err == nil {
		return strings.TrimSpace(host)
	}
	return ""
}

func firstNonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			return ip4.String()
		}
	}
	return ""
}

func sanitizeFileComponent(value string) string {
	replacer := strings.NewReplacer(
		"\\", "_",
		"/", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return strings.Trim(replacer.Replace(strings.TrimSpace(value)), "_")
}

func nativeProfileForTemplate(template Template) (nativeTemplateProfile, error) {
	switch template {
	case TemplateWindows:
		return nativeWindowsProfile(), nil
	case TemplateLinux:
		return nativeLinuxProfile(), nil
	case TemplateEulerOS:
		return nativeEulerOSProfile(), nil
	case TemplateKylin:
		return nativeKylinProfile(), nil
	default:
		return nativeTemplateProfile{}, fmt.Errorf("invalid argument: unsupported benchmark template: %s", template)
	}
}

func nativeProfileForTemplateLevel(template Template, level BaselineLevel) (nativeTemplateProfile, error) {
	profile, err := nativeProfileForTemplate(template)
	if err != nil {
		return nativeTemplateProfile{}, err
	}
	if level == "" {
		level = BaselineLevel1
	}

	switch template {
	case TemplateWindows:
		profile.uuid = "benchmark-windows-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 14:02:39"
			profile.checks = reorderNativeChecks(profile.checks, []string{"8", "6", "4", "9", "2", "12", "1", "5", "0", "7", "3", "10"}, nil)
		case BaselineLevel3:
			profile.templateTime = "2025-06-25 13:20:00"
			profile.checks = reorderNativeChecks(profile.checks, []string{"3", "1", "8", "4", "9", "5", "12", "6", "0", "7", "10", "2"}, nil)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 14:02:45"
			profile.checks = reorderNativeChecks(profile.checks, []string{"6", "8", "4", "9", "1", "12", "5", "2", "0", "7", "3", "10"}, nil)
		}
	case TemplateLinux:
		profile.uuid = "benchmark-linux-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:59:50"
			profile.checks = reorderNativeChecks(profile.checks, []string{"21", "11", "8", "3", "20", "6", "2", "7", "0", "1", "17", "5", "4", "19", "16", "22", "15", "13", "10", "12", "9", "14"}, map[string]string{
				"15": `ps -ef | head -300 | grep -v "\.sh" | grep -v "\.pl"`,
			})
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:59:54"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"21", "1", "11", "8", "3", "7", "4", "10", "0", "5", "6", "14", "19", "2", "22", "15", "17", "13", "20", "12", "9", "16"}, map[string]string{
				"15": `ps -ef | head -300 | grep -v "\.sh" | grep -v "\.pl"`,
			}), linuxLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:59:58"
			profile.checks = reorderNativeChecks(profile.checks, []string{"21", "1", "11", "8", "6", "7", "4", "10", "0", "5", "14", "3", "17", "19", "2", "22", "15", "13", "20", "12", "9", "16"}, map[string]string{
				"15": `ps -ef | head -300 | grep -v "\.sh" | grep -v "\.pl"`,
			})
		}
	case TemplateEulerOS:
		profile.uuid = "benchmark-euleros-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:53:57"
			profile.checks = reorderNativeChecks(profile.checks, []string{"14", "3", "0", "11", "8", "9", "7", "5", "18", "6", "1", "10", "2", "4", "21"}, nil)
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:54:04"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"14", "9", "0", "11", "8", "6", "7", "5", "18", "2", "10", "21", "4", "1", "3"}, nil), eulerLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:54:08"
			profile.checks = reorderNativeChecks(profile.checks, []string{"14", "3", "0", "11", "8", "9", "7", "5", "18", "6", "1", "10", "2", "4", "21"}, nil)
		}
	case TemplateKylin:
		profile.uuid = "benchmark-kylin-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:57:41"
			profile.checks = reorderNativeChecks(profile.checks, []string{"7", "13", "14", "15", "8", "2", "11", "1", "9", "3", "10", "6", "4", "5", "12"}, nil)
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:57:47"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"13", "6", "14", "15", "2", "7", "11", "1", "3", "8", "9", "10", "4", "5", "12"}, nil), kylinLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:57:52"
			profile.checks = reorderNativeChecks(profile.checks, []string{"6", "13", "14", "15", "7", "2", "11", "1", "8", "3", "9", "10", "4", "5", "12"}, nil)
		}
	}
	return profile, nil
}

func reorderNativeChecks(checks []nativeCheck, order []string, overrides map[string]string) []nativeCheck {
	if len(order) == 0 {
		return checks
	}
	index := make(map[string]nativeCheck, len(checks))
	for _, check := range checks {
		if override := strings.TrimSpace(overrides[check.id]); override != "" {
			check.command = override
		}
		index[check.id] = check
	}
	reordered := make([]nativeCheck, 0, len(checks))
	seen := make(map[string]struct{}, len(order))
	for _, id := range order {
		check, ok := index[id]
		if !ok {
			continue
		}
		reordered = append(reordered, check)
		seen[id] = struct{}{}
	}
	for _, check := range checks {
		if _, ok := seen[check.id]; ok {
			continue
		}
		if override := strings.TrimSpace(overrides[check.id]); override != "" {
			check.command = override
		}
		reordered = append(reordered, check)
	}
	return reordered
}

func nativeWindowsProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-windows-native-v1",
		templateTime: "2026-04-27 16:41:43",
		checks: []nativeCheck{
			{id: "8", shell: "powershell", command: `Get-TimeZone | Select-Object DisplayName, Id | ConvertTo-Json -Depth 4`},
			{id: "4", shell: "powershell", command: `Get-CimInstance Win32_UserAccount -Filter "Domain='$env:COMPUTERNAME'" | Select-Object Caption, Description, PasswordChangeable, PasswordExpires, PasswordRequired, Lockout, Status | ConvertTo-Json -Depth 4`},
			{id: "0", command: `netstat -an`, limitNonEmptyLines: 200},
			{id: "9", shell: "powershell", command: `Get-CimInstance Win32_StartupCommand | Select-Object Caption, Command, Location | ConvertTo-Json -Depth 4`, limitNonEmptyLines: 200},
			{id: "12", shell: "powershell", command: `Get-HotFix | Select-Object Description, HotFixID, InstalledOn, InstalledBy | ConvertTo-Json -Depth 4`, limitNonEmptyLines: 200},
			{id: "5", shell: "powershell", command: `Get-CimInstance Win32_Group -Filter "Domain='$env:COMPUTERNAME'" | Select-Object Caption, Description, Status | ConvertTo-Json -Depth 4`},
			{id: "6", shell: "powershell", command: `Get-CimInstance Win32_Service | Select-Object Caption, PathName, StartMode, State | ConvertTo-Json -Depth 4`, limitNonEmptyLines: 200},
			{id: "1", command: `tasklist`, limitNonEmptyLines: 200},
			{id: "3", command: `hostname`},
			{id: "2", shell: "powershell", command: `Get-CimInstance Win32_OperatingSystem | Select-Object Caption, CSDVersion, Version | ConvertTo-Json -Depth 4`},
			{id: "10", shell: "powershell", command: `Get-CimInstance Win32_Share | Select-Object Description, Name, Path | ConvertTo-Json -Depth 4`},
			{id: "7", command: `echo native cleanup not required`},
		},
	}
}

func nativeLinuxProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-linux-native-v1",
		templateTime: "2024-08-08 16:10:15",
		checks: []nativeCheck{
			{id: "6", command: `chkconfig --list | head -50`},
			{id: "3", command: `cat /etc/shadow 2>/dev/null | head -300`},
			{id: "11", command: `lastb -100 2>/dev/null`},
			{id: "5", command: `cat /etc/securetty 2>/dev/null | head -300`},
			{id: "1", command: `cat /etc/passwd 2>/dev/null | head -300`},
			{id: "4", command: `if [ -f /etc/shadow ];then lsattr /etc/shadow 2>/dev/null;fi;
if [ -f /etc/gshadow ];then lsattr /etc/group 2>/dev/null;fi;
if [ -f /etc/passwd ];then lsattr /etc/passwd 2>/dev/null;fi`},
			{id: "20", command: `cat /etc/ftpaccess 2>/dev/null | grep -v "^[[:space:]]*#" | head -300`},
			{id: "8", command: `last -100 2>/dev/null`},
			{id: "14", command: `netstat -anp 2>/dev/null | head -300`},
			{id: "19", command: `cat /etc/ftpaccess 2>/dev/null | grep "^[[:space:]]*banner[[:space:]]*\/.*" | awk '{print $2}' | while read user; do cat "$user";done | grep -v "^[[:space:]]*#" | head -300`},
			{id: "21", command: `rpm -qa | head -100`},
			{id: "13", command: `echo native cleanup not required`},
			{id: "15", command: `ps -ef | grep -v "\.sh" | grep -v "\.pl"`},
			{id: "16", command: `if [ -f /etc/vsftpd.conf ];then cat /etc/vsftpd.conf |grep -v ^#|grep ftpd_banner;elif [ -f /etc/vsftpd/vsftpd.conf ];then cat /etc/vsftpd/vsftpd.conf |grep -v ^#|grep ftpd_banner;fi`},
			{id: "2", command: `cat /etc/group 2>/dev/null | head -300`},
			{id: "9", command: `if [ -f /etc/syslog.conf ];then cat /etc/syslog.conf | grep -v "^[[:space:]]*#" | head -300;elif [ -f /etc/syslog-ng/syslog-ng.conf ];then cat /etc/syslog-ng/syslog-ng.conf | grep -v "^[[:space:]]*#"  | head -300;elif [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#"  | head -300;fi`},
			{id: "7", command: `ifconfig -a 2>/dev/null`},
			{id: "0", command: `uname -a 2>/dev/null`},
			{id: "12", command: `(head -20 /var/log/syslog;head -20 /var/log/messages) 2>/dev/null`},
			{id: "17", command: `cat /etc/vsftpd/chroot_list 2>/dev/null | grep "^[[:space:]]*[^#]" | head -300`},
			{id: "22", command: `version=$(lsb_release -a 2>/dev/null | grep "Description" | awk -F: '{print $2}');if [ -n "$version" ];then echo "$version";else if [ -z "$version" ]; then echo "";else cat /etc/SuSE-release | grep -v "VERSION" | grep -v "PATCHLEVEL";fi;fi`},
			{id: "10", command: `df -m 2>/dev/null`},
		},
	}
}

func linuxLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "LNX-NET-ADV-001", command: `sysctl -n net.ipv4.ip_forward 2>/dev/null || cat /proc/sys/net/ipv4/ip_forward 2>/dev/null`},
		{id: "LNX-NET-ADV-002", command: `sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null`},
		{id: "LNX-NET-ADV-003", command: `sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null`},
		{id: "LNX-NET-ADV-004", command: `sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null`},
		{id: "LNX-NET-ADV-005", command: `sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null`},
		{id: "LNX-SVC-ADV-001", command: `for svc in klogin tftp sendmail echo lpd chargen printer ntalk ypbind bootps discard kshell daytime ident time; do if command -v chkconfig >/dev/null 2>&1; then chkconfig --list 2>/dev/null | grep "^$svc" && echo "$svc"; else systemctl list-units --type=service 2>/dev/null | grep "^$svc" && echo "$svc"; fi; done`},
		{id: "LNX-SVC-ADV-002", command: `ps -ef | grep nfs | grep -v nfsiod | grep -cv "grep nfs"`},
		{id: "LNX-SSH-ADV-001", command: `awk '!/^#/{if ($1 != "") print $1}' /etc/ssh/sshd_config 2>/dev/null | grep -i '^AllowUsers'`},
		{id: "LNX-SSH-ADV-002", command: `ssh_status=$(netstat -antp 2>/dev/null | grep -i listen | grep ":22\\>" | wc -l); if [ "$ssh_status" != "0" ] && [ -f /etc/motd ]; then echo "check result:true"; elif [ "$ssh_status" != "0" ]; then echo "check result:false"; else echo "check result:true"; fi`},
		{id: "LNX-TRUST-001", command: `find / -maxdepth 3 \( -name .rhosts -o -name hosts.equiv \) 2>/dev/null`},
		{id: "LNX-TIME-001", command: `if [ -f /etc/ntp.conf ]; then grep -v "^[[:space:]]*#" /etc/ntp.conf | grep 'server' | grep -v "127.127.1.0" | grep -v "127.0.0.1"; elif [ -f /etc/chrony.conf ]; then grep -v "^[[:space:]]*#" /etc/chrony.conf | grep 'allow' | grep -v "127.127.1.0" | grep -v "127.0.0.1"; fi`},
		{id: "LNX-TIME-002", command: `if pgrep -x "ntpd" >/dev/null || pgrep -x "ntp" >/dev/null; then echo "ntp:start"; fi; if pgrep -x "chronyd" >/dev/null; then echo "chronyd:start"; fi`},
	}
}

func eulerLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "EUL-NET-ADV-001", command: `sysctl -n net.ipv4.ip_forward 2>/dev/null`},
		{id: "EUL-NET-ADV-002", command: `sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null`},
		{id: "EUL-NET-ADV-003", command: `sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null`},
		{id: "EUL-NET-ADV-004", command: `sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null`},
		{id: "EUL-NET-ADV-005", command: `sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null`},
		{id: "EUL-SSH-ADV-001", command: `grep -v '^[[:space:]]*#' /etc/ssh/sshd_config 2>/dev/null | grep Banner`},
		{id: "EUL-LOG-ADV-001", command: `if [ -s /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep "\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]]*";fi`},
		{id: "EUL-LOG-ADV-002", command: `if [ -s /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep "authpriv\.\*[[:space:]]*.*" | grep -Eo '^\s*(.+;|)authpriv\.\*';fi`},
		{id: "EUL-LOG-ADV-003", command: `if [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep "cron\.\*[[:space:]]*" | grep "/var/log/cron";fi`},
		{id: "EUL-TIME-001", command: `if [ -f /etc/ntp.conf ];then cat /etc/ntp.conf | grep -v "^[[:space:]]*#" | grep 'server' | grep -v "127.127.1.0" | grep -v "127.0.0.1";fi`},
		{id: "EUL-TIME-002", command: `systemctl status chronyd 2>/dev/null`},
		{id: "EUL-TIME-003", command: `systemctl status ntpd 2>/dev/null`},
		{id: "EUL-HIST-001", command: `echo $HISTSIZE`},
		{id: "EUL-HIST-002", command: `echo $HISTFILESIZE`},
	}
}

func kylinLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "KYL-TRUST-001", command: `find / -maxdepth 3 \( -name hosts.equiv -o -name .rhosts -o -name .netrc \) 2>/dev/null`},
		{id: "KYL-LOG-ADV-001", command: `if [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep "\*\.info" | grep "/var/log/messages";fi`},
		{id: "KYL-FS-ADV-001", command: `df -k`},
		{id: "KYL-NET-ADV-001", command: `cat /proc/sys/net/ipv4/ip_forward 2>/dev/null`},
		{id: "KYL-NET-ADV-002", command: `sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null`},
		{id: "KYL-NET-ADV-003", command: `sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null`},
		{id: "KYL-NET-ADV-004", command: `sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null`},
		{id: "KYL-NET-ADV-005", command: `sysctl -n net.ipv4.ip_forward 2>/dev/null`},
		{id: "KYL-NET-ADV-006", command: `sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null`},
		{id: "KYL-TIME-001", command: `if [ -f /etc/ntp.conf ];then cat /etc/ntp.conf | grep -v "^[[:space:]]*#" | grep 'server' | grep -v "127.127.1.0" | grep -v "127.0.0.1";fi`},
		{id: "KYL-TIME-002", command: `if pgrep -x "ntpd" >/dev/null || pgrep -x "ntp" >/dev/null; then echo "ntp:start"; else echo "ntp:stop"; fi`},
		{id: "KYL-SSH-ADV-001", command: `ssh_status=$(netstat -antp 2>/dev/null | grep -i listen | grep ":22\\>" | wc -l); if [[ "$ssh_status" != 0 && -f /etc/motd ]];then echo "check result:true"; elif [ "$ssh_status" != 0 ];then echo "check result:false"; else echo "check result:true"; fi`},
		{id: "KYL-LOG-ADV-002", command: `if [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep "authpriv\.\* " | grep "/var/log/secure";fi`},
		{id: "KYL-LOG-ADV-003", command: `if [ -f /etc/rsyslog.conf ];then cat /etc/rsyslog.conf | grep -v "^[[:space:]]*#" | grep -E '[[:space:]]*.+@.+';fi`},
		{id: "KYL-HIST-001", command: `echo $HISTSIZE`},
		{id: "KYL-HIST-002", command: `echo $HISTFILESIZE`},
	}
}

func nativeEulerOSProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-euleros-native-v1",
		templateTime: "2026-04-27 18:37:06",
		checks: []nativeCheck{
			{id: "11", command: `lastb -100 2>/dev/null`},
			{id: "14", command: `netstat -anp 2>/dev/null | head -300`},
			{id: "0", command: `uname -a 2>/dev/null`},
			{id: "7", command: `echo native cleanup not required`},
			{id: "8", command: `last -100 2>/dev/null`},
			{id: "5", command: `cat /etc/securetty 2>/dev/null | head -300`},
			{id: "18", command: `cat /etc/euleros-release`},
			{id: "2", command: `cat /etc/group 2>/dev/null | head -300`},
			{id: "4", command: `chkconfig --list | head -50`},
			{id: "1", command: `cat /etc/passwd 2>/dev/null | head -300`},
			{id: "3", command: `head -20 /var/log/messages 2>/dev/null`},
			{id: "9", command: `grep -E '^\s*AllowUsers\s+|^\s*DenyUsers\s+' /etc/ssh/sshd_config`},
			{id: "10", command: `df -m 2>/dev/null`},
			{id: "21", command: `rpm -qa | head -100`},
			{id: "6", command: `ifconfig -a 2>/dev/null`},
		},
	}
}

func nativeKylinProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-kylin-native-v1",
		templateTime: "2026-04-27 18:37:14",
		checks: []nativeCheck{
			{id: "11", command: `ifconfig -a 2>/dev/null`},
			{id: "13", command: `(head -20 /var/log/syslog;head -20 /var/log/messages) 2>/dev/null`},
			{id: "2", command: `echo native cleanup not required`},
			{id: "14", command: `ps -ef | grep -v "\.sh" | grep -v "\.pl"`},
			{id: "15", command: `netstat -anp 2>/dev/null | head -300`},
			{id: "1", command: `chkconfig --list | head -50`},
			{id: "3", command: `if [ -f /etc/shadow ];then lsattr /etc/shadow 2>/dev/null;fi;
if [ -f /etc/gshadow ];then lsattr /etc/group 2>/dev/null;fi;
if [ -f /etc/passwd ];then lsattr /etc/passwd 2>/dev/null;fi`},
			{id: "4", command: `cat /etc/shadow 2>/dev/null | head -300`},
			{id: "6", command: `cat /etc/group 2>/dev/null | head -300`},
			{id: "5", command: `lastb -100 2>/dev/null`},
			{id: "9", command: `rpm -qa | head -100`},
			{id: "10", command: `df -m 2>/dev/null`},
			{id: "7", command: `uname -a 2>/dev/null`},
			{id: "8", command: `cat /etc/kylin-release`},
			{id: "12", command: `last -100 2>/dev/null`},
		},
	}
}
