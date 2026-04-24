package filterutil

import (
	"strings"
	"testing"

	"edrsystem/internal/processscan"
)

var containsAnySink bool
var hostMatchSink bool

func legacyContainsAnyFold(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(strings.ToLower(haystack), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func legacyHostInfoContainsIP(host processscan.HostInfo, needle string) bool {
	if host.DisplayIP != nil &&
		strings.Contains(strings.ToLower(*host.DisplayIP), strings.ToLower(needle)) {
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

func BenchmarkContainsAnyFoldNew(b *testing.B) {
	haystack := "/opt/java/apache-tomcat-10.1.16/bin/bootstrap.jar --catalina.home=/opt/apache-tomcat"
	needles := []string{"nginx", "iis", "tomcat", "weblogic", "wildfly"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containsAnySink = ContainsAnyFold(haystack, needles)
	}
}

func BenchmarkContainsAnyFoldLegacy(b *testing.B) {
	haystack := "/opt/java/apache-tomcat-10.1.16/bin/bootstrap.jar --catalina.home=/opt/apache-tomcat"
	needles := []string{"nginx", "iis", "tomcat", "weblogic", "wildfly"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containsAnySink = legacyContainsAnyFold(haystack, needles)
	}
}

func BenchmarkHostInfoContainsIPNew(b *testing.B) {
	display := "10.0.0.99"
	host := processscan.HostInfo{
		IPs:         []string{"172.16.12.3", "198.18.0.4", "198.18.0.5"},
		InternalIPs: []string{"192.168.1.100", "192.168.1.101", "10.10.1.6"},
		ExternalIPs: []string{"8.8.8.8", "1.1.1.1"},
		DisplayIP:   &display,
	}
	needle := "198.18"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostMatchSink = HostInfoContainsIP(host, needle)
	}
}

func BenchmarkHostInfoContainsIPLegacy(b *testing.B) {
	display := "10.0.0.99"
	host := processscan.HostInfo{
		IPs:         []string{"172.16.12.3", "198.18.0.4", "198.18.0.5"},
		InternalIPs: []string{"192.168.1.100", "192.168.1.101", "10.10.1.6"},
		ExternalIPs: []string{"8.8.8.8", "1.1.1.1"},
		DisplayIP:   &display,
	}
	needle := "198.18"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hostMatchSink = legacyHostInfoContainsIP(host, needle)
	}
}
