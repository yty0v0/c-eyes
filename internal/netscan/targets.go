package netscan

import (
	"bufio"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

func resolveTargets(params normalizedParams) ([]string, []string, error) {
	var warnings []string

	inputTokens, err := collectTargetTokens(params.Target, params.TargetFile)
	if err != nil {
		return nil, nil, err
	}
	if len(inputTokens) == 0 {
		defaults := defaultTargets(params.IPv6)
		inputTokens = make([]string, 0, len(defaults))
		for _, ip := range defaults {
			inputTokens = append(inputTokens, ip)
		}
	}

	targetSet := map[string]struct{}{}
	for _, token := range inputTokens {
		ips, ws, err := parseTargetToken(token, params.IPv6, params.MaxTargets)
		if err != nil {
			return nil, nil, err
		}
		if len(ws) > 0 {
			warnings = append(warnings, ws...)
		}
		for _, ip := range ips {
			key, ok := normalizeIP(ip.String())
			if !ok {
				continue
			}
			targetSet[key] = struct{}{}
			if len(targetSet) > params.MaxTargets {
				return nil, nil, fmt.Errorf("invalid argument: resolved targets exceed maxTargets (%d)", params.MaxTargets)
			}
		}
	}

	excludeSet := map[string]struct{}{}
	excludeTokens := splitCSV(params.Exclude)
	for _, token := range excludeTokens {
		ips, _, err := parseTargetToken(token, true, params.MaxTargets)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid argument: exclude: %w", err)
		}
		for _, ip := range ips {
			key, ok := normalizeIP(ip.String())
			if !ok {
				continue
			}
			excludeSet[key] = struct{}{}
		}
	}

	targets := make([]string, 0, len(targetSet))
	for ip := range targetSet {
		if _, excluded := excludeSet[ip]; excluded {
			continue
		}
		targets = append(targets, ip)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return compareIPStrings(targets[i], targets[j]) < 0
	})

	if len(targets) == 0 {
		return targets, warnings, nil
	}
	if len(targets) > params.MaxTargets {
		return nil, nil, fmt.Errorf("invalid argument: resolved targets exceed maxTargets (%d)", params.MaxTargets)
	}
	return targets, uniqueStrings(warnings), nil
}

func collectTargetTokens(target, targetFile string) ([]string, error) {
	out := splitCSV(target)
	if strings.TrimSpace(targetFile) == "" {
		return out, nil
	}

	file, err := os.Open(strings.TrimSpace(targetFile))
	if err != nil {
		return nil, fmt.Errorf("invalid argument: targetFile: %w", err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.TrimPrefix(line, "\uFEFF")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, token := range splitCSV(line) {
			out = append(out, token)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("invalid argument: targetFile: %w", err)
	}
	return out, nil
}

func parseTargetToken(token string, ipv6Enabled bool, maxTargets int) ([]net.IP, []string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, nil
	}

	if strings.Contains(token, "/") {
		return expandCIDR(token, ipv6Enabled, maxTargets)
	}
	if strings.Contains(token, "-") {
		return expandRange(token, ipv6Enabled)
	}

	ip := net.ParseIP(token)
	if ip == nil {
		return nil, nil, fmt.Errorf("unsupported target expression: %s", token)
	}
	if ip.To4() == nil && !ipv6Enabled {
		return nil, []string{fmt.Sprintf("IPv6 target skipped because ipv6=false: %s", token)}, nil
	}
	return []net.IP{ip}, nil, nil
}

func expandCIDR(raw string, ipv6Enabled bool, maxTargets int) ([]net.IP, []string, error) {
	ip, ipNet, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid CIDR: %s", raw)
	}
	if ip.To4() == nil && !ipv6Enabled {
		return nil, []string{fmt.Sprintf("IPv6 CIDR skipped because ipv6=false: %s", raw)}, nil
	}

	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits <= 0 {
		return nil, nil, fmt.Errorf("invalid CIDR mask: %s", raw)
	}

	hostBits := bits - ones
	switch {
	case bits == 32 && hostBits > 16:
		return nil, nil, fmt.Errorf("CIDR range too large: %s (reduce to /16 or smaller host range)", raw)
	case bits == 128 && hostBits > 12:
		return nil, nil, fmt.Errorf("CIDR range too large: %s (reduce IPv6 host range to 4096 addresses or less)", raw)
	}

	count := big.NewInt(1)
	count.Lsh(count, uint(hostBits))
	maxAllowed := big.NewInt(int64(maxTargets))
	if count.Cmp(maxAllowed) > 0 {
		return nil, nil, fmt.Errorf("CIDR %s expands beyond maxTargets (%d)", raw, maxTargets)
	}

	base := ip.Mask(ipNet.Mask)
	current := append(net.IP(nil), base...)

	out := make([]net.IP, 0, int(count.Int64()))
	for i := big.NewInt(0); i.Cmp(count) < 0; i.Add(i, big.NewInt(1)) {
		out = append(out, append(net.IP(nil), current...))
		incrementIP(current)
	}
	return out, nil, nil
}

func expandRange(raw string, ipv6Enabled bool) ([]net.IP, []string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Count(raw, "-") != 1 {
		return nil, nil, fmt.Errorf("invalid range: %s", raw)
	}
	parts := strings.SplitN(raw, "-", 2)
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if left == "" || right == "" {
		return nil, nil, fmt.Errorf("invalid range: %s", raw)
	}

	// 192.168.1.10-120
	if strings.Count(left, ".") == 3 && strings.Count(right, ".") == 0 {
		leftIP := net.ParseIP(left)
		if leftIP == nil || leftIP.To4() == nil {
			return nil, nil, fmt.Errorf("invalid IPv4 range start: %s", left)
		}
		endOctet, err := strconv.Atoi(right)
		if err != nil || endOctet < 0 || endOctet > 255 {
			return nil, nil, fmt.Errorf("invalid IPv4 range end: %s", right)
		}
		start4 := leftIP.To4()
		startOctet := int(start4[3])
		if endOctet < startOctet {
			return nil, nil, fmt.Errorf("invalid IPv4 range: end must be >= start")
		}
		out := make([]net.IP, 0, endOctet-startOctet+1)
		for octet := startOctet; octet <= endOctet; octet++ {
			out = append(out, net.IPv4(start4[0], start4[1], start4[2], byte(octet)))
		}
		return out, nil, nil
	}

	start := net.ParseIP(left)
	end := net.ParseIP(right)
	if start == nil || end == nil {
		return nil, nil, fmt.Errorf("invalid range: %s", raw)
	}
	if start.To4() == nil || end.To4() == nil {
		if !ipv6Enabled {
			return nil, []string{fmt.Sprintf("IPv6 range skipped because ipv6=false: %s", raw)}, nil
		}
		return nil, nil, fmt.Errorf("IPv6 ranges are not supported; use IPv6 CIDR with bounded host range")
	}

	start4 := start.To4()
	end4 := end.To4()
	if compareIPs(start4, end4) > 0 {
		return nil, nil, fmt.Errorf("invalid IPv4 range: end must be >= start")
	}

	out := make([]net.IP, 0)
	current := append(net.IP(nil), start4...)
	for compareIPs(current, end4) <= 0 {
		out = append(out, append(net.IP(nil), current...))
		incrementIP(current)
	}
	return out, nil, nil
}

func compareIPStrings(a, b string) int {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	return compareIPs(ipA, ipB)
}

func compareIPs(a, b net.IP) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	a4 := a.To4()
	b4 := b.To4()
	switch {
	case a4 != nil && b4 == nil:
		return -1
	case a4 == nil && b4 != nil:
		return 1
	}

	ba := a.To16()
	bb := b.To16()
	for i := 0; i < len(ba) && i < len(bb); i++ {
		switch {
		case ba[i] < bb[i]:
			return -1
		case ba[i] > bb[i]:
			return 1
		}
	}
	if len(ba) < len(bb) {
		return -1
	}
	if len(ba) > len(bb) {
		return 1
	}
	return 0
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func defaultTargets(ipv6 bool) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return []string{"127.0.0.1"}
	}

	candidates := collectInterfaceCandidates(ifaces, ipv6)
	if len(candidates) == 0 {
		return []string{"127.0.0.1"}
	}

	primaryIPv4 := detectPreferredSourceIP("udp4", "1.1.1.1:80")
	primaryIPv6 := detectPreferredSourceIP("udp6", "[2001:4860:4860::8888]:80")
	chosen := selectPrimaryCandidate(candidates, primaryIPv4, primaryIPv6, ipv6)
	if chosen == nil {
		return []string{"127.0.0.1"}
	}

	targets := buildDefaultTargetsForInterface(*chosen, ipv6, primaryIPv4, primaryIPv6)
	if len(targets) == 0 {
		return []string{"127.0.0.1"}
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return compareIPStrings(targets[i], targets[j]) < 0
	})
	return targets
}

type interfaceCandidate struct {
	Index         int
	PrivateIPv4s  []net.IP
	EligibleIPv6s []net.IP
}

func collectInterfaceCandidates(ifaces []net.Interface, ipv6 bool) []interfaceCandidate {
	out := make([]interfaceCandidate, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		candidate := interfaceCandidate{
			Index: iface.Index,
		}
		for _, addr := range addrs {
			ip, ipNet := addrToIPNet(addr)
			if ip == nil || ipNet == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				if !isPrivateIPv4(v4) {
					continue
				}
				candidate.PrivateIPv4s = append(candidate.PrivateIPv4s, append(net.IP(nil), v4...))
				continue
			}
			if !ipv6 {
				continue
			}
			if !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				continue
			}
			candidate.EligibleIPv6s = append(candidate.EligibleIPv6s, append(net.IP(nil), ip...))
		}
		if len(candidate.PrivateIPv4s) == 0 && len(candidate.EligibleIPv6s) == 0 {
			continue
		}
		out = append(out, candidate)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Index < out[j].Index
	})
	return out
}

func detectPreferredSourceIP(network, remote string) net.IP {
	conn, err := net.Dial(network, remote)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	switch addr := conn.LocalAddr().(type) {
	case *net.UDPAddr:
		if addr.IP == nil {
			return nil
		}
		return append(net.IP(nil), addr.IP...)
	case *net.TCPAddr:
		if addr.IP == nil {
			return nil
		}
		return append(net.IP(nil), addr.IP...)
	default:
		return nil
	}
}

func selectPrimaryCandidate(candidates []interfaceCandidate, primaryIPv4, primaryIPv6 net.IP, ipv6 bool) *interfaceCandidate {
	if len(candidates) == 0 {
		return nil
	}

	for i := range candidates {
		candidate := &candidates[i]
		if primaryIPv4 != nil && candidateHasIP(*candidate, primaryIPv4) {
			return candidate
		}
	}
	if ipv6 && primaryIPv6 != nil {
		for i := range candidates {
			candidate := &candidates[i]
			if candidateHasIP(*candidate, primaryIPv6) {
				return candidate
			}
		}
	}

	for i := range candidates {
		if len(candidates[i].PrivateIPv4s) > 0 {
			return &candidates[i]
		}
	}
	if ipv6 {
		for i := range candidates {
			if len(candidates[i].EligibleIPv6s) > 0 {
				return &candidates[i]
			}
		}
	}
	return nil
}

func candidateHasIP(candidate interfaceCandidate, ip net.IP) bool {
	for _, candidateIP := range candidate.PrivateIPv4s {
		if candidateIP.Equal(ip) {
			return true
		}
	}
	for _, candidateIP := range candidate.EligibleIPv6s {
		if candidateIP.Equal(ip) {
			return true
		}
	}
	return false
}

func buildDefaultTargetsForInterface(candidate interfaceCandidate, ipv6 bool, preferredIPv4, preferredIPv6 net.IP) []string {
	seen := map[string]struct{}{}
	targets := make([]string, 0, 254)

	if len(candidate.PrivateIPv4s) > 0 {
		chosenIPv4 := pickPreferredIP(candidate.PrivateIPv4s, preferredIPv4)
		v4 := chosenIPv4.To4()
		base := net.IPv4(v4[0], v4[1], v4[2], 0)
		for i := 1; i <= 254; i++ {
			entry := net.IPv4(base[12], base[13], base[14], byte(i)).String()
			if _, ok := seen[entry]; ok {
				continue
			}
			seen[entry] = struct{}{}
			targets = append(targets, entry)
		}
	}

	if ipv6 && len(candidate.EligibleIPv6s) > 0 {
		chosenIPv6 := pickPreferredIP(candidate.EligibleIPv6s, preferredIPv6)
		base := chosenIPv6.Mask(net.CIDRMask(120, 128))
		for i := 1; i <= 254; i++ {
			entry := append(net.IP(nil), base...)
			entry[15] = byte(i)
			normalized, ok := normalizeIP(entry.String())
			if !ok {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			targets = append(targets, normalized)
		}
	}

	return targets
}

func pickPreferredIP(candidates []net.IP, preferred net.IP) net.IP {
	if len(candidates) == 0 {
		return nil
	}
	if preferred != nil {
		for _, candidate := range candidates {
			if candidate.Equal(preferred) {
				return candidate
			}
		}
	}
	return candidates[0]
}

func addrToIPNet(addr net.Addr) (net.IP, *net.IPNet) {
	switch typed := addr.(type) {
	case *net.IPNet:
		return typed.IP, typed
	default:
		return nil, nil
	}
}

func isPrivateIPv4(ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	v4 := ip.To4()
	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	default:
		return false
	}
}

func uniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out
}
