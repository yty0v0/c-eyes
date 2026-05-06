//go:build windows

package benchmark

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestLiveCollectWindowsSecurityPolicy(t *testing.T) {
	if os.Getenv("WINDOWS_SECURITY_POLICY_LIVE") != "1" {
		t.Skip("set WINDOWS_SECURITY_POLICY_LIVE=1 to run live security policy collection")
	}

	info0, err := windowsNetUserModalsInfo0()
	t.Logf("windowsNetUserModalsInfo0() = %#v, err=%v", info0, err)

	domainSID, err := windowsLocalAccountDomainSID()
	t.Logf("windowsLocalAccountDomainSID() = %v, err=%v", domainSID, err)

	info3, err := windowsNetUserModalsInfo3()
	t.Logf("windowsNetUserModalsInfo3() = %#v, err=%v", info3, err)

	if domainSID != nil {
		serverHandle, err := windowsSamConnect()
		t.Logf("windowsSamConnect() = %#v, err=%v", serverHandle, err)
		if serverHandle != 0 {
			defer windowsSamCloseHandle(serverHandle)
			for _, access := range []uint32{0x00000001, 0x00000004, 0x00000080, 0x00000100, 0x00000200, 0x00000201, windows.MAXIMUM_ALLOWED} {
				domainHandle, openErr := windowsSamOpenDomainWithAccess(serverHandle, domainSID, access)
				t.Logf("windowsSamOpenDomain(access=0x%x) = %#v, err=%v", access, domainHandle, openErr)
				if domainHandle != 0 {
					buffer, queryErr := windowsSamQueryDomainPasswordInfo(domainHandle)
					t.Logf("windowsSamQueryDomainPasswordInfo(access=0x%x) = %#v, err=%v", access, buffer, queryErr)
					if buffer != 0 {
						windowsSamFreeMemory(buffer)
					}
					windowsSamCloseHandle(domainHandle)
				}
			}
		}

		passwordInfo, err := windowsDomainPasswordInfo(domainSID)
		t.Logf("windowsDomainPasswordInfo() = %#v, err=%v", passwordInfo, err)

		adminInfo, err := windowsBuiltinAccountStatus(domainSID, windows.WinAccountAdministratorSid)
		t.Logf("windowsBuiltinAccountStatus(administrator) = %#v, err=%v", adminInfo, err)

		guestInfo, err := windowsBuiltinAccountStatus(domainSID, windows.WinAccountGuestSid)
		t.Logf("windowsBuiltinAccountStatus(guest) = %#v, err=%v", guestInfo, err)
	}

	allowAnonymousLookup, err := windowsAllowAnonymousNameLookup()
	t.Logf("windowsAllowAnonymousNameLookup() = %t, err=%v", allowAnonymousLookup, err)

	for _, path := range []string{
		`SECURITY\Policy\PolAcDmS`,
		`SECURITY\Policy\PolPrDmS`,
		`SECURITY\Policy\Secrets`,
	} {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			t.Logf("registry.OpenKey(%q) err=%v", path, err)
			continue
		}
		names, err := key.ReadValueNames(-1)
		t.Logf("registry.OpenKey(%q) valueNames=%v err=%v", path, names, err)
		key.Close()
	}

	if values, err := collectWindowsSystemAccessPolicy(); err != nil {
		t.Errorf("collectWindowsSystemAccessPolicy() error = %v", err)
	} else {
		t.Logf("system access: %#v", values)
	}

	if values, err := collectWindowsEventAuditPolicy(); err != nil {
		t.Errorf("collectWindowsEventAuditPolicy() error = %v", err)
	} else {
		t.Logf("event audit: %#v", values)
	}

	if values, err := collectWindowsPrivilegeRightsPolicy(); err != nil {
		t.Errorf("collectWindowsPrivilegeRightsPolicy() error = %v", err)
	} else {
		t.Logf("privilege rights: %#v", values)
	}
}
