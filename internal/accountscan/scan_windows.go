//go:build windows

package accountscan

import (
	"context"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
	errorMoreData       = 234
	nerrSuccess         = 0
	lgIncludeIndirect   = 0x0001
	ufAccountDisable    = 0x0002
	ufLockout           = 0x0010
	timeQForever        = 0xFFFFFFFF
	accountTypeUser     = 1
)

var (
	modNetapi32               = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum           = modNetapi32.NewProc("NetUserEnum")
	procNetUserGetLocalGroups = modNetapi32.NewProc("NetUserGetLocalGroups")
	procNetUserGetGroups      = modNetapi32.NewProc("NetUserGetGroups")
	procNetApiBufferFree      = modNetapi32.NewProc("NetApiBufferFree")
)

type userInfo3 struct {
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

type localGroupUsersInfo0 struct {
	Name *uint16
}

type groupUsersInfo0 struct {
	Name *uint16
}

type windowsUser struct {
	Name           string
	FullName       string
	Comment        string
	Flags          uint32
	LastLogon      uint32
	AcctExpires    uint32
	PasswordAge    uint32
	UserID         uint32
	PrimaryGroupID uint32
	HomeDir        string
}

type windowsAccountAPI interface {
	EnumUsers() ([]windowsUser, error)
	LocalGroups(name string) ([]string, error)
	GlobalGroups(name string) ([]string, error)
	SID(name string) (string, error)
}

type netUserAPI struct{}

var windowsAPIProvider = func() windowsAccountAPI {
	return &netUserAPI{}
}

func collectAccounts(ctx context.Context) ([]AccountInfo, error) {
	_ = ctx
	api := windowsAPIProvider()
	users, err := api.EnumUsers()
	if err != nil {
		return nil, err
	}

	now := nowFn()
	out := make([]AccountInfo, 0, len(users))
	for _, user := range users {
		localGroups, _ := api.LocalGroups(user.Name)
		globalGroups, _ := api.GlobalGroups(user.Name)
		allGroups := dedupeAndSortGroups(append(localGroups, globalGroups...))

		sid, _ := api.SID(user.Name)
		uid := int64(user.UserID)
		if uid == 0 && sid != "" {
			uid = sidHash(sid)
		}
		gid := int64(user.PrimaryGroupID)
		if gid == 0 && sid != "" {
			gid = sidHash("group:" + sid)
		}

		status := windowsAccountStatus(user.Flags)
		account := AccountInfo{
			UID:         nonZeroInt64Ptr(uid),
			GID:         nonZeroInt64Ptr(gid),
			Groups:      allGroups,
			Name:        nullableString(user.Name),
			Status:      intPtr(status),
			Home:        nullableString(user.HomeDir),
			FullName:    nullableString(user.FullName),
			Description: nullableString(user.Comment),
			Type:        intPtr(accountTypeUser),
		}

		if user.LastLogon > 0 {
			t := time.Unix(int64(user.LastLogon), 0)
			account.LastLoginTime = &t
		}
		if user.PasswordAge > 0 {
			t := now.Add(-time.Duration(user.PasswordAge) * time.Second)
			account.LastChangPwdTime = &t
		}
		if user.AcctExpires != 0 && user.AcctExpires != timeQForever {
			expire := time.Unix(int64(user.AcctExpires), 0)
			account.ExpireTime = &expire
			expired := expire.Before(now)
			account.Expired = &expired
		}

		out = append(out, account)
	}
	return out, nil
}

func (n *netUserAPI) EnumUsers() ([]windowsUser, error) {
	var (
		resume uint32
		out    []windowsUser
	)
	for {
		var (
			buf     uintptr
			entries uint32
			total   uint32
		)
		r0, _, _ := procNetUserEnum.Call(
			0,
			3,
			filterNormalAccount,
			uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)
		if buf != 0 {
			records := unsafe.Slice((*userInfo3)(unsafe.Pointer(buf)), int(entries))
			for _, rec := range records {
				out = append(out, windowsUser{
					Name:           utf16PtrToString(rec.Name),
					FullName:       utf16PtrToString(rec.FullName),
					Comment:        firstNonEmpty(utf16PtrToString(rec.Comment), utf16PtrToString(rec.UserComment)),
					Flags:          rec.Flags,
					LastLogon:      rec.LastLogon,
					AcctExpires:    rec.AcctExpires,
					PasswordAge:    rec.PasswordAge,
					UserID:         rec.UserID,
					PrimaryGroupID: rec.PrimaryGroupID,
					HomeDir:        utf16PtrToString(rec.HomeDir),
				})
			}
			_, _, _ = procNetApiBufferFree.Call(buf)
		}
		if r0 == nerrSuccess {
			break
		}
		if r0 != errorMoreData {
			return nil, syscall.Errno(r0)
		}
	}
	return out, nil
}

func (n *netUserAPI) LocalGroups(name string) ([]string, error) {
	userPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	var (
		buf     uintptr
		entries uint32
		total   uint32
	)
	r0, _, _ := procNetUserGetLocalGroups.Call(
		0,
		uintptr(unsafe.Pointer(userPtr)),
		0,
		lgIncludeIndirect,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entries)),
		uintptr(unsafe.Pointer(&total)),
	)
	defer func() {
		if buf != 0 {
			_, _, _ = procNetApiBufferFree.Call(buf)
		}
	}()
	if r0 != nerrSuccess {
		return nil, syscall.Errno(r0)
	}
	records := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buf)), int(entries))
	out := make([]string, 0, len(records))
	for _, rec := range records {
		if g := utf16PtrToString(rec.Name); g != "" {
			out = append(out, g)
		}
	}
	return out, nil
}

func (n *netUserAPI) GlobalGroups(name string) ([]string, error) {
	userPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	var (
		buf     uintptr
		entries uint32
		total   uint32
	)
	r0, _, _ := procNetUserGetGroups.Call(
		0,
		uintptr(unsafe.Pointer(userPtr)),
		0,
		uintptr(unsafe.Pointer(&buf)),
		maxPreferredLength,
		uintptr(unsafe.Pointer(&entries)),
		uintptr(unsafe.Pointer(&total)),
	)
	defer func() {
		if buf != 0 {
			_, _, _ = procNetApiBufferFree.Call(buf)
		}
	}()
	if r0 != nerrSuccess {
		return nil, syscall.Errno(r0)
	}
	records := unsafe.Slice((*groupUsersInfo0)(unsafe.Pointer(buf)), int(entries))
	out := make([]string, 0, len(records))
	for _, rec := range records {
		if g := utf16PtrToString(rec.Name); g != "" {
			out = append(out, g)
		}
	}
	return out, nil
}

func (n *netUserAPI) SID(name string) (string, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}

	var sidLen uint32
	var domainLen uint32
	var use uint32
	_ = windows.LookupAccountName(nil, namePtr, nil, &sidLen, nil, &domainLen, &use)
	if sidLen == 0 {
		return "", syscall.EINVAL
	}

	sidBuf := make([]byte, sidLen)
	var domainPtr *uint16
	var domain []uint16
	if domainLen > 0 {
		domain = make([]uint16, domainLen)
		domainPtr = &domain[0]
	}
	sid := (*windows.SID)(unsafe.Pointer(&sidBuf[0]))
	if err := windows.LookupAccountName(nil, namePtr, sid, &sidLen, domainPtr, &domainLen, &use); err != nil {
		return "", err
	}
	return sid.String(), nil
}

func dedupeAndSortGroups(groups []string) []string {
	if len(groups) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func windowsAccountStatus(flags uint32) int {
	if flags&ufAccountDisable != 0 {
		return 2
	}
	if flags&ufLockout != 0 {
		return 1
	}
	return 0
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	return windows.UTF16PtrToString(ptr)
}

func sidHash(sid string) int64 {
	var hash int64 = 1469598103934665603
	for _, r := range sid {
		hash ^= int64(r)
		hash *= 1099511628211
	}
	if hash < 0 {
		hash = -hash
	}
	return hash
}

func nonZeroInt64Ptr(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
