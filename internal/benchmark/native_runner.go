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
