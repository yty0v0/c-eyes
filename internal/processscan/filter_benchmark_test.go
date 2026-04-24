package processscan

import (
	"strings"
	"testing"
)

var hostIPMatchSink bool

func legacyHostIPMatch(host HostInfo, needle string) bool {
	if host.DisplayIP != nil && strings.Contains(strings.ToLower(*host.DisplayIP), strings.ToLower(needle)) {
		return true
	}
	for _, ip := range host.InternalIPs {
		if strings.Contains(strings.ToLower(ip), strings.ToLower(needle)) {
			return true
		}
	}
	for _, ip := range host.ExternalIPs {
		if strings.Contains(strings.ToLower(ip), strings.ToLower(needle)) {
			return true
		}
	}
	for _, ip := range host.IPs {
		if strings.Contains(strings.ToLower(ip), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func BenchmarkHostIPMatchNew(b *testing.B) {
	display := "10.0.0.99"
	host := HostInfo{
		IPs:         []string{"172.16.12.3", "198.18.0.4", "198.18.0.5"},
		InternalIPs: []string{"192.168.1.100", "192.168.1.101", "10.10.1.6"},
		ExternalIPs: []string{"8.8.8.8", "1.1.1.1"},
		DisplayIP:   &display,
	}
	needle := strings.ToLower("198.18")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostIPMatchSink = hostIPMatch(host, needle)
	}
}

func BenchmarkHostIPMatchLegacy(b *testing.B) {
	display := "10.0.0.99"
	host := HostInfo{
		IPs:         []string{"172.16.12.3", "198.18.0.4", "198.18.0.5"},
		InternalIPs: []string{"192.168.1.100", "192.168.1.101", "10.10.1.6"},
		ExternalIPs: []string{"8.8.8.8", "1.1.1.1"},
		DisplayIP:   &display,
	}
	needle := "198.18"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostIPMatchSink = legacyHostIPMatch(host, needle)
	}
}
