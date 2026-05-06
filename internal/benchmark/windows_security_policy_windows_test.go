//go:build windows

package benchmark

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDurationValues(t *testing.T) {
	t.Parallel()

	if got := windowsDurationDaysValue(42 * 24 * 60 * 60); got != "42" {
		t.Fatalf("windowsDurationDaysValue() = %q, want %q", got, "42")
	}
	if got := windowsDurationDaysValue(windowsTimeForever); got != "-1" {
		t.Fatalf("windowsDurationDaysValue(forever) = %q, want %q", got, "-1")
	}
	if got := windowsDurationMinutesValue(10 * 60); got != "10" {
		t.Fatalf("windowsDurationMinutesValue() = %q, want %q", got, "10")
	}
}

func TestWindowsAuditOptionValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		auditing bool
		option   uint32
		want     string
	}{
		{name: "disabled", auditing: false, option: windowsPolicyAuditEventSuccess | windowsPolicyAuditEventFailure, want: "0"},
		{name: "none", auditing: true, option: windowsPolicyAuditEventNone, want: "0"},
		{name: "success", auditing: true, option: windowsPolicyAuditEventSuccess, want: "1"},
		{name: "failure", auditing: true, option: windowsPolicyAuditEventFailure, want: "2"},
		{name: "success_failure", auditing: true, option: windowsPolicyAuditEventSuccess | windowsPolicyAuditEventFailure, want: "3"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := windowsAuditOptionValue(tc.auditing, tc.option); got != tc.want {
				t.Fatalf("windowsAuditOptionValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWindowsPolicyAllowsAnonymousLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sddl string
		want bool
	}{
		{name: "allow", sddl: "D:(A;;0x00000800;;;AN)", want: true},
		{name: "deny", sddl: "D:(D;;0x00000800;;;AN)(A;;0x00000800;;;AN)", want: false},
		{name: "missing", sddl: "D:(A;;FA;;;SY)", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString(%q) error = %v", tc.sddl, err)
			}
			if got := windowsPolicyAllowsAnonymousLookup(sd); got != tc.want {
				t.Fatalf("windowsPolicyAllowsAnonymousLookup() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestWindowsPrivilegeMemberMatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		item   string
		member string
		want   bool
	}{
		{item: "Guest", member: "Guest", want: true},
		{item: "HOST\\Guest", member: "Guest", want: true},
		{item: "*S-1-5-32-544", member: "Guest", want: false},
		{item: "Users", member: "Guest", want: false},
	}
	for _, tc := range cases {
		if got := windowsPrivilegeMemberMatches(tc.item, tc.member); got != tc.want {
			t.Fatalf("windowsPrivilegeMemberMatches(%q, %q) = %t, want %t", tc.item, tc.member, got, tc.want)
		}
	}
}

func TestSplitWindowsPolicyRegistryLocation(t *testing.T) {
	t.Parallel()

	keyPath, valueName, err := splitWindowsPolicyRegistryLocation(`MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash`)
	if err != nil {
		t.Fatalf("splitWindowsPolicyRegistryLocation() error = %v", err)
	}
	if keyPath != `System\CurrentControlSet\Control\Lsa` {
		t.Fatalf("keyPath = %q, want %q", keyPath, `System\CurrentControlSet\Control\Lsa`)
	}
	if valueName != "NoLMHash" {
		t.Fatalf("valueName = %q, want %q", valueName, "NoLMHash")
	}
}
