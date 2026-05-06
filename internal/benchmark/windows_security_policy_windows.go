//go:build windows

package benchmark

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	windowsNetUserModalsLevel0 = 0
	windowsNetUserModalsLevel2 = 2
	windowsNetUserModalsLevel3 = 3
	windowsNetUserInfoLevel3   = 3

	windowsUserFlagAccountDisable = 0x0002
	windowsTimeForever            = 0xFFFFFFFF

	windowsPolicyViewLocalInformation = 0x00000001
	windowsPolicyViewAuditInformation = 0x00000002
	windowsPolicyLookupNames          = 0x00000800
	windowsPolicyAuditEventsInfoClass = 2

	windowsPolicyAuditEventSuccess = 0x00000001
	windowsPolicyAuditEventFailure = 0x00000002
	windowsPolicyAuditEventNone    = 0x00000004

	windowsDomainPasswordComplex        = 0x00000001
	windowsDomainLockoutAdmins          = 0x00000008
	windowsDomainPasswordStoreCleartext = 0x00000010
	windowsDomainPasswordInfoClass      = 1
	windowsSamServerConnect             = windows.MAXIMUM_ALLOWED
	windowsDomainReadPasswordParams     = 0x00000001
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modNetapi32 = windows.NewLazySystemDLL("netapi32.dll")
	modSamlib   = windows.NewLazySystemDLL("samlib.dll")

	procLsaOpenPolicy                     = modAdvapi32.NewProc("LsaOpenPolicy")
	procLsaQueryInformationPolicy         = modAdvapi32.NewProc("LsaQueryInformationPolicy")
	procLsaQuerySecurityObject            = modAdvapi32.NewProc("LsaQuerySecurityObject")
	procLsaEnumerateAccountsWithUserRight = modAdvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaFreeMemory                     = modAdvapi32.NewProc("LsaFreeMemory")
	procLsaClose                          = modAdvapi32.NewProc("LsaClose")
	procLsaNtStatusToWinError             = modAdvapi32.NewProc("LsaNtStatusToWinError")

	procNetUserModalsGet = modNetapi32.NewProc("NetUserModalsGet")
	procNetUserGetInfo   = modNetapi32.NewProc("NetUserGetInfo")
	procNetApiBufferFree = modNetapi32.NewProc("NetApiBufferFree")

	procSamConnect                = modSamlib.NewProc("SamConnect")
	procSamOpenDomain             = modSamlib.NewProc("SamOpenDomain")
	procSamQueryInformationDomain = modSamlib.NewProc("SamQueryInformationDomain")
	procSamFreeMemory             = modSamlib.NewProc("SamFreeMemory")
	procSamCloseHandle            = modSamlib.NewProc("SamCloseHandle")

	windowsSecurityPolicyPrivilegesOnce sync.Once
	windowsSecurityPolicyPrivilegesErr  error
)

type windowsUserModalsInfo0 struct {
	MinPasswordLength uint32
	MaxPasswordAge    uint32
	MinPasswordAge    uint32
	ForceLogoff       uint32
	PasswordHistLen   uint32
}

type windowsUserModalsInfo2 struct {
	DomainName *uint16
	DomainID   *windows.SID
}

type windowsUserModalsInfo3 struct {
	LockoutDuration          uint32
	LockoutObservationWindow uint32
	LockoutThreshold         uint32
}

type windowsUserInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UserComment     *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPWCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

type windowsLsaHandle uintptr

type windowsLsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type windowsLsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *windowsLsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type windowsPolicyAuditEventsInfo struct {
	AuditingMode           byte
	EventAuditingOptions   *uint32
	MaximumAuditEventCount uint32
}

type windowsLsaEnumerationInformation struct {
	SID *windows.SID
}

type windowsSamHandle uintptr

type windowsSamObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *windowsLsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type windowsDomainPasswordInformation struct {
	MinPasswordLength     uint16
	PasswordHistoryLength uint16
	PasswordProperties    uint32
	MaxPasswordAge        int64
	MinPasswordAge        int64
}

type windowsBuiltinAccountInfo struct {
	Name     string
	Disabled bool
}

var windowsPrivilegeRightsKeys = []string{
	"SeDenyInteractiveLogonRight",
	"SeDenyNetworkLogonRight",
	"SeNetworkLogonRight",
}

var windowsAuditCategoryKeys = []string{
	"AuditSystemEvents",
	"AuditLogonEvents",
	"AuditObjectAccess",
	"AuditPrivilegeUse",
	"AuditProcessTracking",
	"AuditPolicyChange",
	"AuditAccountManage",
	"AuditDSAccess",
	"AuditAccountLogon",
}

func (s *windowsBenchmarkCollectorState) systemAccessPolicy(_ context.Context) (map[string]string, error) {
	if s.systemAccessLoaded {
		return s.systemAccess, s.systemAccessErr
	}
	s.systemAccess, s.systemAccessErr = collectWindowsSystemAccessPolicy()
	s.systemAccessLoaded = true
	return s.systemAccess, s.systemAccessErr
}

func (s *windowsBenchmarkCollectorState) eventAuditPolicy(_ context.Context) (map[string]string, error) {
	if s.eventAuditLoaded {
		return s.eventAudit, s.eventAuditErr
	}
	s.eventAudit, s.eventAuditErr = collectWindowsEventAuditPolicy()
	s.eventAuditLoaded = true
	return s.eventAudit, s.eventAuditErr
}

func (s *windowsBenchmarkCollectorState) privilegeRightsPolicy(_ context.Context) (map[string][]string, error) {
	if s.privilegeRightsLoaded {
		return s.privilegeRights, s.privilegeRightsErr
	}
	s.privilegeRights, s.privilegeRightsErr = collectWindowsPrivilegeRightsPolicy()
	s.privilegeRightsLoaded = true
	return s.privilegeRights, s.privilegeRightsErr
}

func collectWindowsSecurityPolicy(_ context.Context) error {
	return windowsEnableSecurityPolicyPrivileges()
}

func windowsEnableSecurityPolicyPrivileges() error {
	windowsSecurityPolicyPrivilegesOnce.Do(func() {
		for _, name := range []string{"SeSecurityPrivilege", "SeBackupPrivilege", "SeRestorePrivilege"} {
			if err := windowsEnableCurrentProcessPrivilege(name); err != nil && !errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
				windowsSecurityPolicyPrivilegesErr = err
				return
			}
		}
	})
	return windowsSecurityPolicyPrivilegesErr
}

func windowsEnableCurrentProcessPrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return err
	}

	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil); err != nil {
		return err
	}
	if err := windows.GetLastError(); err != nil && err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func collectWindowsSystemAccessPolicy() (map[string]string, error) {
	if err := windowsEnableSecurityPolicyPrivileges(); err != nil {
		return nil, err
	}

	info0, err := windowsNetUserModalsInfo0()
	if err != nil {
		return nil, err
	}
	domainSID, err := windowsLocalAccountDomainSID()
	if err != nil {
		return nil, err
	}
	info3, err := windowsNetUserModalsInfo3()
	if err != nil {
		return nil, err
	}
	adminInfo, err := windowsBuiltinAccountStatus(domainSID, windows.WinAccountAdministratorSid)
	if err != nil {
		return nil, err
	}
	guestInfo, err := windowsBuiltinAccountStatus(domainSID, windows.WinAccountGuestSid)
	if err != nil {
		return nil, err
	}
	allowAnonymousLookup, err := windowsAllowAnonymousNameLookup()
	if err != nil {
		return nil, err
	}

	values := map[string]string{
		"MinimumPasswordLength":  strconv.FormatUint(uint64(info0.MinPasswordLength), 10),
		"PasswordHistorySize":    strconv.FormatUint(uint64(info0.PasswordHistLen), 10),
		"MaximumPasswordAge":     windowsDurationDaysValue(info0.MaxPasswordAge),
		"MinimumPasswordAge":     windowsDurationDaysValue(info0.MinPasswordAge),
		"LockoutBadCount":        strconv.FormatUint(uint64(info3.LockoutThreshold), 10),
		"ResetLockoutCount":      windowsDurationMinutesValue(info3.LockoutObservationWindow),
		"LockoutDuration":        windowsDurationMinutesValue(info3.LockoutDuration),
		"EnableGuestAccount":     windowsBoolPolicyValue(!guestInfo.Disabled),
		"NewAdministratorName":   adminInfo.Name,
		"NewGuestName":           guestInfo.Name,
		"LSAAnonymousNameLookup": windowsBoolPolicyValue(allowAnonymousLookup),
		"EnableAdminAccount":     windowsBoolPolicyValue(!adminInfo.Disabled),
	}

	passwordInfo, err := windowsDomainPasswordInfo(domainSID)
	if err == nil {
		values["PasswordComplexity"] = windowsBoolPolicyValue(passwordInfo.PasswordProperties&windowsDomainPasswordComplex != 0)
		values["AllowAdministratorLockout"] = windowsBoolPolicyValue(passwordInfo.PasswordProperties&windowsDomainLockoutAdmins != 0)
		values["ClearTextPassword"] = windowsBoolPolicyValue(passwordInfo.PasswordProperties&windowsDomainPasswordStoreCleartext != 0)
	}

	return values, nil
}

func collectWindowsEventAuditPolicy() (map[string]string, error) {
	if err := windowsEnableSecurityPolicyPrivileges(); err != nil {
		return nil, err
	}
	handle, err := windowsOpenPolicy(windowsPolicyViewAuditInformation)
	if err != nil {
		return nil, err
	}
	defer windowsLsaClose(handle)

	var buffer uintptr
	status, _, _ := procLsaQueryInformationPolicy.Call(
		uintptr(handle),
		uintptr(windowsPolicyAuditEventsInfoClass),
		uintptr(unsafe.Pointer(&buffer)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return nil, err
	}
	defer windowsLsaFreeMemory(buffer)

	info := (*windowsPolicyAuditEventsInfo)(unsafe.Pointer(buffer))
	values := map[string]string{}
	var options []uint32
	if info.EventAuditingOptions != nil && info.MaximumAuditEventCount > 0 {
		options = unsafe.Slice(info.EventAuditingOptions, int(info.MaximumAuditEventCount))
	}
	for idx, key := range windowsAuditCategoryKeys {
		var option uint32
		if idx < len(options) {
			option = options[idx]
		}
		values[key] = windowsAuditOptionValue(info.AuditingMode != 0, option)
	}
	return values, nil
}

func collectWindowsPrivilegeRightsPolicy() (map[string][]string, error) {
	if err := windowsEnableSecurityPolicyPrivileges(); err != nil {
		return nil, err
	}
	handle, err := windowsOpenPolicy(windowsPolicyViewLocalInformation | windowsPolicyLookupNames)
	if err != nil {
		return nil, err
	}
	defer windowsLsaClose(handle)

	values := make(map[string][]string, len(windowsPrivilegeRightsKeys))
	for _, right := range windowsPrivilegeRightsKeys {
		items, err := windowsEnumerateAccountsWithUserRight(handle, right)
		if err != nil {
			return nil, err
		}
		values[right] = items
	}
	return values, nil
}

func windowsOpenPolicy(desiredAccess uint32) (windowsLsaHandle, error) {
	attrs := windowsLsaObjectAttributes{
		Length: uint32(unsafe.Sizeof(windowsLsaObjectAttributes{})),
	}
	var handle windowsLsaHandle
	status, _, _ := procLsaOpenPolicy.Call(
		0,
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&handle)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return 0, err
	}
	return handle, nil
}

func windowsLsaClose(handle windowsLsaHandle) {
	if handle == 0 {
		return
	}
	_, _, _ = procLsaClose.Call(uintptr(handle))
}

func windowsLsaFreeMemory(buffer uintptr) {
	if buffer == 0 {
		return
	}
	_, _, _ = procLsaFreeMemory.Call(buffer)
}

func windowsLsaStatusError(status uintptr) error {
	if status == 0 {
		return nil
	}
	winErr, _, _ := procLsaNtStatusToWinError.Call(status)
	if winErr == 0 {
		return syscall.Errno(status)
	}
	return syscall.Errno(winErr)
}

func windowsNetUserModalsInfo0() (windowsUserModalsInfo0, error) {
	buffer, err := windowsNetUserModalsGet(windowsNetUserModalsLevel0)
	if err != nil {
		return windowsUserModalsInfo0{}, err
	}
	defer windowsNetApiBufferFree(buffer)
	return *(*windowsUserModalsInfo0)(unsafe.Pointer(buffer)), nil
}

func windowsLocalAccountDomainSID() (*windows.SID, error) {
	buffer, err := windowsNetUserModalsGet(windowsNetUserModalsLevel2)
	if err != nil {
		return nil, err
	}
	defer windowsNetApiBufferFree(buffer)

	info := (*windowsUserModalsInfo2)(unsafe.Pointer(buffer))
	if info.DomainID == nil {
		return nil, errors.New("local account domain SID is missing")
	}
	return info.DomainID.Copy()
}

func windowsNetUserModalsInfo3() (windowsUserModalsInfo3, error) {
	buffer, err := windowsNetUserModalsGet(windowsNetUserModalsLevel3)
	if err != nil {
		return windowsUserModalsInfo3{}, err
	}
	defer windowsNetApiBufferFree(buffer)
	return *(*windowsUserModalsInfo3)(unsafe.Pointer(buffer)), nil
}

func windowsNetUserModalsGet(level uint32) (uintptr, error) {
	var buffer uintptr
	r0, _, _ := procNetUserModalsGet.Call(
		0,
		uintptr(level),
		uintptr(unsafe.Pointer(&buffer)),
	)
	if r0 != 0 {
		return 0, syscall.Errno(r0)
	}
	return buffer, nil
}

func windowsNetApiBufferFree(buffer uintptr) {
	if buffer == 0 {
		return
	}
	_, _, _ = procNetApiBufferFree.Call(buffer)
}

func windowsBuiltinAccountStatus(domainSID *windows.SID, sidType windows.WELL_KNOWN_SID_TYPE) (windowsBuiltinAccountInfo, error) {
	accountSID, err := windows.CreateWellKnownDomainSid(sidType, domainSID)
	if err != nil {
		return windowsBuiltinAccountInfo{}, err
	}
	name, _, _, err := accountSID.LookupAccount("")
	if err != nil {
		return windowsBuiltinAccountInfo{}, err
	}
	info, err := windowsNetUserInfo3(name)
	if err != nil {
		return windowsBuiltinAccountInfo{}, err
	}
	return windowsBuiltinAccountInfo{
		Name:     name,
		Disabled: info.Flags&windowsUserFlagAccountDisable != 0,
	}, nil
}

func windowsNetUserInfo3(name string) (windowsUserInfo3, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return windowsUserInfo3{}, err
	}
	var buffer uintptr
	r0, _, _ := procNetUserGetInfo.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(windowsNetUserInfoLevel3),
		uintptr(unsafe.Pointer(&buffer)),
	)
	if r0 != 0 {
		return windowsUserInfo3{}, syscall.Errno(r0)
	}
	defer windowsNetApiBufferFree(buffer)
	return *(*windowsUserInfo3)(unsafe.Pointer(buffer)), nil
}

func windowsDomainPasswordInfo(domainSID *windows.SID) (windowsDomainPasswordInformation, error) {
	serverHandle, err := windowsSamConnect()
	if err != nil {
		return windowsDomainPasswordInformation{}, err
	}
	defer windowsSamCloseHandle(serverHandle)

	domainHandle, err := windowsSamOpenDomain(serverHandle, domainSID)
	if err != nil {
		return windowsDomainPasswordInformation{}, err
	}
	defer windowsSamCloseHandle(domainHandle)

	buffer, err := windowsSamQueryDomainPasswordInfo(domainHandle)
	if err != nil {
		return windowsDomainPasswordInformation{}, err
	}
	defer windowsSamFreeMemory(buffer)

	return *(*windowsDomainPasswordInformation)(unsafe.Pointer(buffer)), nil
}

func windowsSamConnect() (windowsSamHandle, error) {
	attrs := windowsSamObjectAttributes{
		Length: uint32(unsafe.Sizeof(windowsSamObjectAttributes{})),
	}
	var handle windowsSamHandle
	status, _, _ := procSamConnect.Call(
		0,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(windowsSamServerConnect),
		uintptr(unsafe.Pointer(&attrs)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return 0, err
	}
	return handle, nil
}

func windowsSamOpenDomain(serverHandle windowsSamHandle, domainSID *windows.SID) (windowsSamHandle, error) {
	return windowsSamOpenDomainWithAccess(serverHandle, domainSID, windowsDomainReadPasswordParams)
}

func windowsSamOpenDomainWithAccess(serverHandle windowsSamHandle, domainSID *windows.SID, desiredAccess uint32) (windowsSamHandle, error) {
	var handle windowsSamHandle
	status, _, _ := procSamOpenDomain.Call(
		uintptr(serverHandle),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(domainSID)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return 0, err
	}
	return handle, nil
}

func windowsSamQueryDomainPasswordInfo(domainHandle windowsSamHandle) (uintptr, error) {
	var buffer uintptr
	status, _, _ := procSamQueryInformationDomain.Call(
		uintptr(domainHandle),
		uintptr(windowsDomainPasswordInfoClass),
		uintptr(unsafe.Pointer(&buffer)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return 0, err
	}
	return buffer, nil
}

func windowsSamCloseHandle(handle windowsSamHandle) {
	if handle == 0 {
		return
	}
	_, _, _ = procSamCloseHandle.Call(uintptr(handle))
}

func windowsSamFreeMemory(buffer uintptr) {
	if buffer == 0 {
		return
	}
	_, _, _ = procSamFreeMemory.Call(buffer)
}

func windowsAllowAnonymousNameLookup() (bool, error) {
	handle, err := windowsOpenPolicy(uint32(windows.READ_CONTROL))
	if err != nil {
		return false, err
	}
	defer windowsLsaClose(handle)

	var descriptor *windows.SECURITY_DESCRIPTOR
	status, _, _ := procLsaQuerySecurityObject.Call(
		uintptr(handle),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		return false, err
	}
	defer windowsLsaFreeMemory(uintptr(unsafe.Pointer(descriptor)))

	return windowsPolicyAllowsAnonymousLookup(descriptor), nil
}

func windowsPolicyAllowsAnonymousLookup(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	if descriptor == nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND)
	}
	if dacl == nil {
		return true
	}

	anonymousSID, err := windows.CreateWellKnownSid(windows.WinAnonymousSid)
	if err != nil {
		return false
	}
	for idx := uint32(0); idx < uint32(dacl.AceCount); idx++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, idx, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Mask&windowsPolicyLookupNames == 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !aceSID.Equals(anonymousSID) {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			return false
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			return true
		}
	}
	return false
}

func windowsEnumerateAccountsWithUserRight(handle windowsLsaHandle, right string) ([]string, error) {
	rightValue, rightBuf, err := windowsNewLsaUnicodeString(right)
	if err != nil {
		return nil, err
	}
	_ = rightBuf

	var buffer uintptr
	var count uint32
	status, _, _ := procLsaEnumerateAccountsWithUserRight.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&rightValue)),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&count)),
	)
	if err := windowsLsaStatusError(status); err != nil {
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return nil, nil
		}
		return nil, err
	}
	defer windowsLsaFreeMemory(buffer)

	entries := unsafe.Slice((*windowsLsaEnumerationInformation)(unsafe.Pointer(buffer)), int(count))
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.SID == nil {
			continue
		}
		name, _, _, err := entry.SID.LookupAccount("")
		if err != nil || strings.TrimSpace(name) == "" {
			out = append(out, entry.SID.String())
			continue
		}
		out = append(out, name)
	}
	return windowsDedupeSortStrings(out), nil
}

func windowsNewLsaUnicodeString(value string) (windowsLsaUnicodeString, []uint16, error) {
	if value == "" {
		return windowsLsaUnicodeString{}, nil, nil
	}
	buf, err := windows.UTF16FromString(value)
	if err != nil {
		return windowsLsaUnicodeString{}, nil, err
	}
	return windowsLsaUnicodeString{
		Length:        uint16((len(buf) - 1) * 2),
		MaximumLength: uint16(len(buf) * 2),
		Buffer:        &buf[0],
	}, buf, nil
}

func windowsDedupeSortStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(value)]; ok {
			continue
		}
		seen[strings.ToLower(value)] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func windowsDurationDaysValue(seconds uint32) string {
	if seconds == windowsTimeForever {
		return "-1"
	}
	return strconv.FormatUint(uint64(seconds)/(24*60*60), 10)
}

func windowsDurationMinutesValue(seconds uint32) string {
	if seconds == windowsTimeForever {
		return "-1"
	}
	return strconv.FormatUint(uint64(seconds)/60, 10)
}

func windowsBoolPolicyValue(enabled bool) string {
	if enabled {
		return "1"
	}
	return "0"
}

func windowsAuditOptionValue(auditingMode bool, option uint32) string {
	if !auditingMode || option == 0 || option&windowsPolicyAuditEventNone != 0 {
		return "0"
	}
	value := 0
	if option&windowsPolicyAuditEventSuccess != 0 {
		value |= 1
	}
	if option&windowsPolicyAuditEventFailure != 0 {
		value |= 2
	}
	return strconv.Itoa(value)
}

func readWindowsPolicyRegistryValue(location string) (string, error) {
	keyPath, valueName, err := splitWindowsPolicyRegistryLocation(location)
	if err != nil {
		return "", err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()

	if value, _, err := key.GetStringValue(valueName); err == nil {
		return strings.TrimSpace(value), nil
	} else if err != nil && !errors.Is(err, registry.ErrUnexpectedType) && !errors.Is(err, registry.ErrNotExist) {
		return "", err
	}
	if value, _, err := key.GetIntegerValue(valueName); err == nil {
		return strconv.FormatUint(value, 10), nil
	} else if err != nil && !errors.Is(err, registry.ErrUnexpectedType) && !errors.Is(err, registry.ErrNotExist) {
		return "", err
	}
	if value, _, err := key.GetStringsValue(valueName); err == nil {
		return strings.Join(value, ","), nil
	} else if err != nil && !errors.Is(err, registry.ErrUnexpectedType) && !errors.Is(err, registry.ErrNotExist) {
		return "", err
	}
	if value, _, err := key.GetBinaryValue(valueName); err == nil {
		return fmt.Sprintf("%x", value), nil
	} else if err != nil && !errors.Is(err, registry.ErrUnexpectedType) && !errors.Is(err, registry.ErrNotExist) {
		return "", err
	}
	return "", nil
}

func splitWindowsPolicyRegistryLocation(location string) (string, string, error) {
	location = strings.TrimSpace(location)
	if !strings.HasPrefix(strings.ToUpper(location), "MACHINE\\") {
		return "", "", fmt.Errorf("unsupported policy registry location %q", location)
	}
	trimmed := location[len("MACHINE\\"):]
	idx := strings.LastIndex(trimmed, `\`)
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", fmt.Errorf("invalid policy registry location %q", location)
	}
	return trimmed[:idx], trimmed[idx+1:], nil
}

func trimPolicyValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.Trim(trimmed, `"`)
	return trimmed
}

func collectWindowsPolicyCheck(ctx context.Context, state *windowsBenchmarkCollectorState, title, section, key string) (benchmarkCheckResult, error) {
	var value string
	switch section {
	case "system_access", "event_audit":
		switch section {
		case "system_access":
			values, err := state.systemAccessPolicy(ctx)
			if err != nil {
				return benchmarkCheckResult{}, err
			}
			value = values[key]
		case "event_audit":
			values, err := state.eventAuditPolicy(ctx)
			if err != nil {
				return benchmarkCheckResult{}, err
			}
			value = values[key]
		}
	case "registry":
		lookupValue, err := readWindowsPolicyRegistryValue(key)
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		value = trimPolicyValue(lookupValue)
	default:
		return benchmarkCheckResult{}, fmt.Errorf("unsupported policy section %q", section)
	}

	actual := fmt.Sprintf("%s=%s", title, value)
	evidence := mustMarshalPrettyJSON(map[string]any{
		"section": section,
		"key":     key,
		"value":   value,
	})
	eval := map[string]any{}
	if strings.TrimSpace(value) != "" {
		eval["value"] = value
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			eval["int_value"] = n
		}
	}
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: evidence,
		Eval:     eval,
	}, nil
}

func collectWindowsPrivilegeMembershipCheck(ctx context.Context, state *windowsBenchmarkCollectorState, privilege, member string) (benchmarkCheckResult, error) {
	policy, err := state.privilegeRightsPolicy(ctx)
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	items := policy[privilege]
	contains := false
	for _, item := range items {
		if windowsPrivilegeMemberMatches(item, member) {
			contains = true
			break
		}
	}
	actual := fmt.Sprintf("%s contains %s = %t", privilege, member, contains)
	evidence := mustMarshalPrettyJSON(map[string]any{
		"section": "privilege_rights",
		"key":     privilege,
		"items":   items,
	})
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: evidence,
		Eval: map[string]any{
			"contains_member": contains,
		},
	}, nil
}

func windowsPrivilegeMemberMatches(item, member string) bool {
	item = strings.TrimSpace(strings.TrimPrefix(item, "*"))
	member = strings.TrimSpace(strings.TrimPrefix(member, "*"))
	if strings.EqualFold(item, member) {
		return true
	}
	return strings.EqualFold(windowsShortAccountName(item), windowsShortAccountName(member))
}

func windowsShortAccountName(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.LastIndex(value, `\`); idx >= 0 && idx < len(value)-1 {
		return value[idx+1:]
	}
	return value
}

func parsePolicyInt(value string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return n
}
