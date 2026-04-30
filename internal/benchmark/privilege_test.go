package benchmark

import (
	"strings"
	"testing"
)

func TestValidatePrivilegeWindowsNonAdmin(t *testing.T) {
	t.Parallel()

	err := validatePrivilege("windows", false, 0)
	if err == nil {
		t.Fatal("expected privilege error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "administrator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatePrivilegeLinuxNonRoot(t *testing.T) {
	t.Parallel()

	err := validatePrivilege("linux", false, 1000)
	if err == nil {
		t.Fatal("expected privilege error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "root") {
		t.Fatalf("unexpected error: %v", err)
	}
}
