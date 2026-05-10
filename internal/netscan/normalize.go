package netscan

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

var defaultTCPPorts = []int{22, 80, 135, 139, 443, 445, 3389}
var defaultUDPPorts = []int{53, 137, 161}

func normalizeParams(input Params) (normalizedParams, error) {
	params := normalizedParams{Params: input}

	params.ScanModes = normalizeModes(input.ScanModes)
	if len(params.ScanModes) == 0 {
		params.ScanModes = []ScanMode{DefaultScanMode}
	}

	if input.MaxTargets <= 0 {
		params.MaxTargets = DefaultMaxTargets
	}
	if params.MaxTargets <= 0 {
		params.MaxTargets = DefaultMaxTargets
	}

	if input.PPS <= 0 {
		params.PPS = DefaultPPS
	}
	if params.PPS > MaxPPS {
		return params, fmt.Errorf("invalid argument: pps must be between 1 and %d", MaxPPS)
	}

	if input.Workers <= 0 {
		params.Workers = DefaultWorkers
	}
	if params.Workers > MaxWorkers {
		return params, fmt.Errorf("invalid argument: workers must be between 1 and %d", MaxWorkers)
	}

	if input.TimeoutMs <= 0 {
		params.TimeoutMs = DefaultTimeoutMS
	}
	if params.TimeoutMs < 50 {
		return params, fmt.Errorf("invalid argument: timeoutMs must be >= 50")
	}

	if input.JitterMs < 0 {
		return params, fmt.Errorf("invalid argument: jitterMs must be >= 0")
	}
	if input.JitterMs == 0 {
		params.JitterMs = DefaultJitterMS
	}

	params.Timeout = time.Duration(params.TimeoutMs) * time.Millisecond
	params.Jitter = time.Duration(params.JitterMs) * time.Millisecond

	params.TCPPorts = normalizePorts(input.TCPPorts)
	params.UDPPorts = normalizePorts(input.UDPPorts)
	if len(params.TCPPorts) == 0 {
		params.TCPPorts = append([]int{}, defaultTCPPorts...)
	}
	if len(params.UDPPorts) == 0 {
		params.UDPPorts = append([]int{}, defaultUDPPorts...)
	}

	params.AssetStatus = strings.ToLower(strings.TrimSpace(input.AssetStatus))
	if params.AssetStatus != "" && params.AssetStatus != "managed" && params.AssetStatus != "unmanaged" && params.AssetStatus != "ignored" {
		return params, fmt.Errorf("invalid argument: assetStatus only supports managed/unmanaged/ignored")
	}

	params.Keyword = strings.TrimSpace(input.Keyword)
	params.SortBy = strings.ToLower(strings.TrimSpace(input.SortBy))
	params.SortOrder = strings.ToLower(strings.TrimSpace(input.SortOrder))
	if params.SortBy == "" {
		params.SortBy = strings.ToLower(DefaultSortBy)
	}
	switch params.SortBy {
	case "lastseen", "firstseen", "ipaddress", "assetstatus":
	default:
		return params, fmt.Errorf("invalid argument: sortBy only supports lastSeen/firstSeen/ipAddress/assetStatus")
	}
	if params.SortOrder == "" {
		params.SortOrder = DefaultSortOrder
	}
	if params.SortOrder != "asc" && params.SortOrder != "desc" {
		return params, fmt.Errorf("invalid argument: sortOrder only supports asc/desc")
	}

	return params, nil
}

func normalizeModes(input []ScanMode) []ScanMode {
	if len(input) == 0 {
		return nil
	}
	seen := map[ScanMode]struct{}{}
	out := make([]ScanMode, 0, len(input))
	for _, mode := range input {
		key := ScanMode(strings.ToUpper(strings.TrimSpace(string(mode))))
		if key == "" {
			continue
		}
		if _, ok := modeCapabilities[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	slices.SortFunc(out, func(a, b ScanMode) int {
		return slices.Index(allModes, a) - slices.Index(allModes, b)
	})
	return out
}

func normalizePorts(input []int) []int {
	if len(input) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(input))
	out := make([]int, 0, len(input))
	for _, port := range input {
		if port < 1 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
	}
	slices.Sort(out)
	return out
}

func normalizeIP(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), true
	}
	return strings.ToLower(ip.String()), true
}

func normalizeMAC(raw string) (string, bool) {
	trimmed := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(raw, "-", ":"), ".", ""), " ", ""))
	if trimmed == "" {
		return "", false
	}
	if strings.Contains(trimmed, ":") {
		mac, err := net.ParseMAC(trimmed)
		if err != nil {
			return "", false
		}
		return strings.ToUpper(mac.String()), true
	}
	compact := strings.ToUpper(trimmed)
	if len(compact) != 12 {
		return "", false
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i < len(compact); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(compact[i : i+2])
	}
	mac, err := net.ParseMAC(b.String())
	if err != nil {
		return "", false
	}
	return strings.ToUpper(mac.String()), true
}

func deterministicAssetID(ip, mac string) string {
	base := "ip:" + strings.TrimSpace(ip)
	if strings.TrimSpace(mac) != "" {
		base = "mac:" + strings.TrimSpace(mac)
	}
	sum := sha1.Sum([]byte(base))
	return hex.EncodeToString(sum[:])
}

func ipVersion(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return "unknown"
	}
	if parsed.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func optionalString(raw string) *string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}
