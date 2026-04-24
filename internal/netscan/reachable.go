package netscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	reachableCandidateLimit          = 128
	reachableVerificationTargetLimit = 4
)

var reachableVerificationTCPPorts = []int{445, 3389, 22, 80}

var (
	reachabilityRouteCollector      = collectRouteCandidates
	reachabilityConnectionCollector = collectConnectionCandidates
	reachabilityICMPProbe           = probeICMP
	reachabilityTCPPortProbe        = probeTCPPort
)

type reachabilitySignal struct {
	CIDR    string
	NextHop string
	Source  string
}

type reachabilityCandidate struct {
	CIDR    string
	NextHop string
	Sources []string
}

func discoverAndVerifyReachableSegments(ctx context.Context, params normalizedParams) ([]ReachableSegmentMetric, []string, []string) {
	routeSignals, routeWarnings := reachabilityRouteCollector()
	connectionSignals, connectionWarnings := reachabilityConnectionCollector()
	warnings := append([]string{}, routeWarnings...)
	warnings = append(warnings, connectionWarnings...)

	candidates, normalizeWarnings := mergeReachabilitySignals(append(routeSignals, connectionSignals...))
	warnings = append(warnings, normalizeWarnings...)
	if len(candidates) == 0 {
		return []ReachableSegmentMetric{}, []string{}, uniqueStrings(warnings)
	}

	if len(candidates) > reachableCandidateLimit {
		warnings = append(warnings, fmt.Sprintf("reachableSegments: candidate segment count %d exceeds internal limit %d; truncating", len(candidates), reachableCandidateLimit))
		candidates = candidates[:reachableCandidateLimit]
	}

	icmpEnabled := true
	if err := checkPermissionForMode(ModeICMPEcho, false); err != nil {
		icmpEnabled = false
		warnings = append(warnings, fmt.Sprintf("reachableSegments: ICMP verification unavailable: %v", err))
	}

	metrics := make([]ReachableSegmentMetric, 0, len(candidates))
	verifiedTargets := make([]string, 0, len(candidates))
	verifiedTargetSet := map[string]struct{}{}

	for _, candidate := range candidates {
		metric := ReachableSegmentMetric{
			CIDR:             candidate.CIDR,
			DiscoverySources: append([]string{}, candidate.Sources...),
			NextHop:          optionalString(candidate.NextHop),
			Verified:         false,
		}

		targets := buildVerificationTargets(candidate)
		if len(targets) == 0 {
			warnings = append(warnings, fmt.Sprintf("reachableSegments: no verification targets for candidate %s", candidate.CIDR))
			metrics = append(metrics, metric)
			continue
		}
		if len(targets) > reachableVerificationTargetLimit {
			warnings = append(warnings, fmt.Sprintf("reachableSegments: verification targets for %s exceed internal limit %d; truncating", candidate.CIDR, reachableVerificationTargetLimit))
			targets = targets[:reachableVerificationTargetLimit]
		}

		verifyTarget, verifyMethod, verified, verifyWarnings := verifyCandidateReachability(ctx, targets, params.Timeout, icmpEnabled)
		warnings = append(warnings, verifyWarnings...)
		if verified {
			metric.Verified = true
			metric.VerificationTarget = optionalString(verifyTarget)
			metric.VerificationMethod = optionalString(verifyMethod)
			if _, ok := verifiedTargetSet[verifyTarget]; !ok {
				verifiedTargetSet[verifyTarget] = struct{}{}
				verifiedTargets = append(verifiedTargets, verifyTarget)
			}
		}
		metrics = append(metrics, metric)
	}

	sort.SliceStable(metrics, func(i, j int) bool {
		return compareIPStringsCIDR(metrics[i].CIDR, metrics[j].CIDR) < 0
	})
	sort.SliceStable(verifiedTargets, func(i, j int) bool {
		return compareIPStrings(verifiedTargets[i], verifiedTargets[j]) < 0
	})
	return metrics, verifiedTargets, uniqueStrings(warnings)
}

func mergeReachabilitySignals(signals []reachabilitySignal) ([]reachabilityCandidate, []string) {
	if len(signals) == 0 {
		return []reachabilityCandidate{}, nil
	}
	warnings := []string{}
	merged := map[string]*reachabilityCandidate{}

	for _, signal := range signals {
		normalizedCIDR, ok, warning := normalizeReachabilityCIDR(signal.CIDR)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if !ok {
			continue
		}

		entry, exists := merged[normalizedCIDR]
		if !exists {
			entry = &reachabilityCandidate{
				CIDR:    normalizedCIDR,
				NextHop: "",
				Sources: []string{},
			}
			merged[normalizedCIDR] = entry
		}
		if source := normalizeReachabilitySource(signal.Source); source != "" {
			entry.Sources = appendIfMissing(entry.Sources, source)
		}
		if nh, ok := normalizeReachabilityNextHop(signal.NextHop); ok && entry.NextHop == "" {
			entry.NextHop = nh
		}
	}

	candidates := make([]reachabilityCandidate, 0, len(merged))
	for _, candidate := range merged {
		candidate.Sources = uniqueStrings(candidate.Sources)
		if len(candidate.Sources) == 0 {
			candidate.Sources = []string{"unknown"}
		}
		candidates = append(candidates, *candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return compareIPStringsCIDR(candidates[i].CIDR, candidates[j].CIDR) < 0
	})
	return candidates, uniqueStrings(warnings)
}

func normalizeReachabilityCIDR(raw string) (string, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false, "reachableSegments: empty CIDR candidate skipped"
	}
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", false, fmt.Sprintf("reachableSegments: invalid CIDR candidate skipped: %s", raw)
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", false, fmt.Sprintf("reachableSegments: non-IPv4 candidate skipped: %s", raw)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones <= 0 || ones > 31 {
		return "", false, fmt.Sprintf("reachableSegments: unsupported CIDR mask skipped: %s", raw)
	}
	network := v4.Mask(ipNet.Mask).To4()
	if network == nil || !isPrivateIPv4(network) {
		return "", false, fmt.Sprintf("reachableSegments: non-private candidate skipped: %s", raw)
	}
	return fmt.Sprintf("%s/%d", network.String(), ones), true, ""
}

func normalizeReachabilityNextHop(raw string) (string, bool) {
	normalized, ok := normalizeIP(raw)
	if !ok {
		return "", false
	}
	parsed := net.ParseIP(normalized)
	if parsed == nil || parsed.To4() == nil || !isPrivateIPv4(parsed.To4()) {
		return "", false
	}
	return normalized, true
}

func normalizeReachabilitySource(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	return raw
}

func buildVerificationTargets(candidate reachabilityCandidate) []string {
	seen := map[string]struct{}{}
	targets := make([]string, 0, reachableVerificationTargetLimit)
	add := func(value string) {
		normalized, ok := normalizeIP(value)
		if !ok {
			return
		}
		parsed := net.ParseIP(normalized)
		if parsed == nil || parsed.To4() == nil || !isPrivateIPv4(parsed.To4()) {
			return
		}
		if _, exists := seen[normalized]; exists {
			return
		}
		seen[normalized] = struct{}{}
		targets = append(targets, normalized)
	}

	add(candidate.NextHop)

	_, ipNet, err := net.ParseCIDR(candidate.CIDR)
	if err != nil {
		return targets
	}
	network := ipNet.IP.To4()
	if network == nil {
		return targets
	}
	for _, octet := range []byte{1, 2, 254} {
		probe := net.IPv4(network[0], network[1], network[2], octet)
		if !ipNet.Contains(probe) {
			continue
		}
		add(probe.String())
	}
	return targets
}

func verifyCandidateReachability(
	ctx context.Context,
	targets []string,
	timeout time.Duration,
	icmpEnabled bool,
) (string, string, bool, []string) {
	warnings := []string{}
	probeTimeout := timeout
	if probeTimeout <= 0 {
		probeTimeout = 900 * time.Millisecond
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			warnings = append(warnings, fmt.Sprintf("reachableSegments: verification interrupted for %s: %v", target, ctx.Err()))
			return "", "", false, warnings
		}
		if icmpEnabled {
			alive, err := reachabilityICMPProbe(target, ModeICMPEcho, probeTimeout)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("reachableSegments: ICMP verification warning for %s: %v", target, err))
			}
			if alive {
				return target, "icmp_echo", true, warnings
			}
		}
		for _, port := range reachableVerificationTCPPorts {
			if reachabilityTCPPortProbe(ctx, target, port, probeTimeout) {
				return target, fmt.Sprintf("tcp_connect:%d", port), true, warnings
			}
		}
	}
	return "", "", false, warnings
}

func mergeVerifiedTargets(baseTargets, verifiedTargets []string, maxTargets int) ([]string, []string) {
	warnings := []string{}
	if maxTargets <= 0 {
		maxTargets = DefaultMaxTargets
	}
	merged := make([]string, 0, len(baseTargets)+len(verifiedTargets))
	seen := map[string]struct{}{}
	for _, item := range baseTargets {
		normalized, ok := normalizeIP(item)
		if !ok {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		merged = append(merged, normalized)
	}
	for _, item := range verifiedTargets {
		normalized, ok := normalizeIP(item)
		if !ok {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		if len(merged) >= maxTargets {
			warnings = append(warnings, fmt.Sprintf("reachableSegments: verified target skipped because maxTargets reached: %s", normalized))
			continue
		}
		seen[normalized] = struct{}{}
		merged = append(merged, normalized)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		return compareIPStrings(merged[i], merged[j]) < 0
	})
	return merged, uniqueStrings(warnings)
}

func compareIPStringsCIDR(a, b string) int {
	parsePrefix := func(value string) string {
		value = strings.TrimSpace(value)
		parts := strings.SplitN(value, "/", 2)
		return strings.TrimSpace(parts[0])
	}
	return compareIPStrings(parsePrefix(a), parsePrefix(b))
}
