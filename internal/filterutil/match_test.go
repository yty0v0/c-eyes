package filterutil

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestContainsFold(t *testing.T) {
	if !ContainsFold("Alpha-Beta", "beta") {
		t.Fatalf("expected case-insensitive match")
	}
	if ContainsFold("Alpha-Beta", "gamma") {
		t.Fatalf("did not expect mismatch to match")
	}
}

func TestContainsAnyFold(t *testing.T) {
	needles := []string{"nginx", "tomcat", "apache"}
	if !ContainsAnyFold("JAVA process with TomCat bootstrap", needles) {
		t.Fatalf("expected contains-any case-insensitive match")
	}
	if ContainsAnyFold("postgres background worker", needles) {
		t.Fatalf("did not expect contains-any match")
	}
}

func TestHostInfoContainsIP(t *testing.T) {
	display := "10.0.0.99"
	host := processscan.HostInfo{
		IPs:         []string{"172.16.12.3"},
		InternalIPs: []string{"192.168.1.100"},
		ExternalIPs: []string{"8.8.8.8"},
		DisplayIP:   &display,
	}

	if !HostInfoContainsIP(host, "8.8.8") {
		t.Fatalf("expected external IP match")
	}
	if !HostInfoContainsIP(host, "10.0.0.9") {
		t.Fatalf("expected display IP match")
	}
	if HostInfoContainsIP(host, "203.0.113") {
		t.Fatalf("did not expect unmatched IP to match")
	}
}
