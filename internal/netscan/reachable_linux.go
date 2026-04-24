//go:build linux

package netscan

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func collectRouteCandidates() ([]reachabilitySignal, []string) {
	content, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, []string{fmt.Sprintf("reachableSegments: route collector unavailable on linux: %v", err)}
	}
	lines := strings.Split(string(content), "\n")
	if len(lines) <= 1 {
		return []reachabilitySignal{}, nil
	}
	out := make([]reachabilitySignal, 0, len(lines)-1)
	for _, raw := range lines[1:] {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 8 {
			continue
		}
		dest, ok := parseProcRouteHexIPv4(fields[1])
		if !ok {
			continue
		}
		mask, ok := parseProcRouteHexIPv4(fields[7])
		if !ok {
			continue
		}
		maskBytes := net.IPMask(mask.To4())
		ones, bits := maskBytes.Size()
		if bits != 32 || ones <= 0 || ones > 31 {
			continue
		}
		network := dest.Mask(maskBytes).To4()
		if network == nil || !isPrivateIPv4(network) {
			continue
		}

		nextHop := ""
		if gateway, ok := parseProcRouteHexIPv4(fields[2]); ok {
			if gatewayV4 := gateway.To4(); gatewayV4 != nil && isPrivateIPv4(gatewayV4) && !gatewayV4.Equal(net.IPv4zero) {
				nextHop = gatewayV4.String()
			}
		}

		out = append(out, reachabilitySignal{
			CIDR:    fmt.Sprintf("%s/%d", network.String(), ones),
			NextHop: nextHop,
			Source:  "route_table",
		})
	}
	return out, nil
}

func collectConnectionCandidates() ([]reachabilitySignal, []string) {
	content, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, []string{fmt.Sprintf("reachableSegments: connection collector unavailable on linux: %v", err)}
	}
	lines := strings.Split(string(content), "\n")
	if len(lines) <= 1 {
		return []reachabilitySignal{}, nil
	}
	out := make([]reachabilitySignal, 0, len(lines)-1)
	for _, raw := range lines[1:] {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 4 {
			continue
		}
		// 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		remote := strings.SplitN(fields[2], ":", 2)
		if len(remote) != 2 {
			continue
		}
		ip, ok := parseProcRouteHexIPv4(remote[0])
		if !ok {
			continue
		}
		v4 := ip.To4()
		if v4 == nil || !isPrivateIPv4(v4) {
			continue
		}
		cidr := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
		out = append(out, reachabilitySignal{
			CIDR:   cidr,
			Source: "active_connections",
		})
	}
	return out, nil
}

func parseProcRouteHexIPv4(raw string) (net.IP, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) != 8 {
		return nil, false
	}
	value, err := strconv.ParseUint(raw, 16, 32)
	if err != nil {
		return nil, false
	}
	u := uint32(value)
	return net.IPv4(byte(u), byte(u>>8), byte(u>>16), byte(u>>24)).To4(), true
}
