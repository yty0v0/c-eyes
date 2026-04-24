package processscan

import (
	"reflect"
	"testing"
)

func TestIsExternalRemoteIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "public_ipv4", ip: "8.8.8.8", want: true},
		{name: "public_ipv6", ip: "2001:4860:4860::8888", want: true},
		{name: "private_ipv4", ip: "10.0.0.1", want: false},
		{name: "loopback", ip: "127.0.0.1", want: false},
		{name: "unspecified", ip: "0.0.0.0", want: false},
		{name: "invalid", ip: "not-an-ip", want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := isExternalRemoteIP(tc.ip); got != tc.want {
				t.Fatalf("isExternalRemoteIP(%q)=%v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestMergeAndNormalizeProcessExternalIPMap(t *testing.T) {
	m := map[int][]string{}
	mergeProcessExternalIP(m, 123, "8.8.4.4")
	mergeProcessExternalIP(m, 123, "1.1.1.1")
	mergeProcessExternalIP(m, 123, "8.8.4.4")
	normalizeProcessExternalIPMap(m)

	got := m[123]
	want := []string{"1.1.1.1", "8.8.4.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected merged ip list: got=%v want=%v", got, want)
	}
}
