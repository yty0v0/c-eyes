package benchmark

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

type nativeCheck struct {
	id string
}

type nativeTemplateProfile struct {
	uuid         string
	templateTime string
	checks       []nativeCheck
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
			profile.checks = reorderNativeChecks(profile.checks, []string{"8", "6", "4", "9", "2", "12", "1", "5", "0", "7", "3", "10"})
		case BaselineLevel3:
			profile.templateTime = "2025-06-25 13:20:00"
			profile.checks = reorderNativeChecks(profile.checks, []string{"3", "1", "8", "4", "9", "5", "12", "6", "0", "7", "10", "2"})
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 14:02:45"
			profile.checks = reorderNativeChecks(profile.checks, []string{"6", "8", "4", "9", "1", "12", "5", "2", "0", "7", "3", "10"})
		}
	case TemplateLinux:
		profile.uuid = "benchmark-linux-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:59:50"
			profile.checks = reorderNativeChecks(profile.checks, []string{"21", "11", "8", "3", "20", "6", "2", "7", "0", "1", "17", "5", "4", "19", "16", "22", "15", "13", "10", "12", "9", "14"})
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:59:54"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"21", "1", "11", "8", "3", "7", "4", "10", "0", "5", "6", "14", "19", "2", "22", "15", "17", "13", "20", "12", "9", "16"}), linuxLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:59:58"
			profile.checks = reorderNativeChecks(profile.checks, []string{"21", "1", "11", "8", "6", "7", "4", "10", "0", "5", "14", "3", "17", "19", "2", "22", "15", "13", "20", "12", "9", "16"})
		}
	case TemplateEulerOS:
		profile.uuid = "benchmark-euleros-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:53:57"
			profile.checks = reorderNativeChecks(profile.checks, []string{"14", "3", "0", "11", "8", "9", "7", "5", "18", "6", "1", "10", "2", "4", "21"})
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:54:04"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"14", "9", "0", "11", "8", "6", "7", "5", "18", "2", "10", "21", "4", "1", "3"}), eulerLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:54:08"
			profile.checks = reorderNativeChecks(profile.checks, []string{"14", "3", "0", "11", "8", "9", "7", "5", "18", "6", "1", "10", "2", "4", "21"})
		}
	case TemplateKylin:
		profile.uuid = "benchmark-kylin-native-v" + string(level)
		switch level {
		case BaselineLevel2:
			profile.templateTime = "2026-04-29 13:57:41"
			profile.checks = reorderNativeChecks(profile.checks, []string{"7", "13", "14", "15", "8", "2", "11", "1", "9", "3", "10", "6", "4", "5", "12"})
		case BaselineLevel3:
			profile.templateTime = "2026-04-29 13:57:47"
			profile.checks = append(reorderNativeChecks(profile.checks, []string{"13", "6", "14", "15", "2", "7", "11", "1", "3", "8", "9", "10", "4", "5", "12"}), kylinLevel3AdvancedChecks()...)
		case BaselineLevel4:
			profile.templateTime = "2026-04-29 13:57:52"
			profile.checks = reorderNativeChecks(profile.checks, []string{"6", "13", "14", "15", "7", "2", "11", "1", "8", "3", "9", "10", "4", "5", "12"})
		}
	}
	return profile, nil
}

func reorderNativeChecks(checks []nativeCheck, order []string) []nativeCheck {
	if len(order) == 0 {
		return checks
	}
	index := make(map[string]nativeCheck, len(checks))
	for _, check := range checks {
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
		reordered = append(reordered, check)
	}
	return reordered
}

func nativeWindowsProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-windows-native-v1",
		templateTime: "2026-04-27 16:41:43",
		checks: []nativeCheck{
			{id: "8"},
			{id: "4"},
			{id: "0"},
			{id: "9"},
			{id: "12"},
			{id: "5"},
			{id: "6"},
			{id: "1"},
			{id: "3"},
			{id: "2"},
			{id: "10"},
			{id: "7"},
		},
	}
}

func nativeLinuxProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-linux-native-v1",
		templateTime: "2024-08-08 16:10:15",
		checks: []nativeCheck{
			{id: "6"},
			{id: "3"},
			{id: "11"},
			{id: "5"},
			{id: "1"},
			{id: "4"},
			{id: "20"},
			{id: "8"},
			{id: "14"},
			{id: "19"},
			{id: "21"},
			{id: "13"},
			{id: "15"},
			{id: "16"},
			{id: "2"},
			{id: "9"},
			{id: "7"},
			{id: "0"},
			{id: "12"},
			{id: "17"},
			{id: "22"},
			{id: "10"},
		},
	}
}

func linuxLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "LNX-NET-ADV-001"},
		{id: "LNX-NET-ADV-002"},
		{id: "LNX-NET-ADV-003"},
		{id: "LNX-NET-ADV-004"},
		{id: "LNX-NET-ADV-005"},
		{id: "LNX-SVC-ADV-001"},
		{id: "LNX-SVC-ADV-002"},
		{id: "LNX-SSH-ADV-001"},
		{id: "LNX-SSH-ADV-002"},
		{id: "LNX-TRUST-001"},
		{id: "LNX-TIME-001"},
		{id: "LNX-TIME-002"},
	}
}

func eulerLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "EUL-NET-ADV-001"},
		{id: "EUL-NET-ADV-002"},
		{id: "EUL-NET-ADV-003"},
		{id: "EUL-NET-ADV-004"},
		{id: "EUL-NET-ADV-005"},
		{id: "EUL-SSH-ADV-001"},
		{id: "EUL-LOG-ADV-001"},
		{id: "EUL-LOG-ADV-002"},
		{id: "EUL-LOG-ADV-003"},
		{id: "EUL-TIME-001"},
		{id: "EUL-TIME-002"},
		{id: "EUL-TIME-003"},
		{id: "EUL-HIST-001"},
		{id: "EUL-HIST-002"},
	}
}

func kylinLevel3AdvancedChecks() []nativeCheck {
	return []nativeCheck{
		{id: "KYL-TRUST-001"},
		{id: "KYL-LOG-ADV-001"},
		{id: "KYL-FS-ADV-001"},
		{id: "KYL-NET-ADV-001"},
		{id: "KYL-NET-ADV-002"},
		{id: "KYL-NET-ADV-003"},
		{id: "KYL-NET-ADV-004"},
		{id: "KYL-NET-ADV-005"},
		{id: "KYL-NET-ADV-006"},
		{id: "KYL-TIME-001"},
		{id: "KYL-TIME-002"},
		{id: "KYL-SSH-ADV-001"},
		{id: "KYL-LOG-ADV-002"},
		{id: "KYL-LOG-ADV-003"},
		{id: "KYL-HIST-001"},
		{id: "KYL-HIST-002"},
	}
}

func nativeEulerOSProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-euleros-native-v1",
		templateTime: "2026-04-27 18:37:06",
		checks: []nativeCheck{
			{id: "11"},
			{id: "14"},
			{id: "0"},
			{id: "7"},
			{id: "8"},
			{id: "5"},
			{id: "18"},
			{id: "2"},
			{id: "4"},
			{id: "1"},
			{id: "3"},
			{id: "9"},
			{id: "10"},
			{id: "21"},
			{id: "6"},
		},
	}
}

func nativeKylinProfile() nativeTemplateProfile {
	return nativeTemplateProfile{
		uuid:         "benchmark-kylin-native-v1",
		templateTime: "2026-04-27 18:37:14",
		checks: []nativeCheck{
			{id: "11"},
			{id: "13"},
			{id: "2"},
			{id: "14"},
			{id: "15"},
			{id: "1"},
			{id: "3"},
			{id: "4"},
			{id: "6"},
			{id: "5"},
			{id: "9"},
			{id: "10"},
			{id: "7"},
			{id: "8"},
			{id: "12"},
		},
	}
}
