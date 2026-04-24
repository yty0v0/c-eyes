//go:build windows

package usergroupscan

import (
	"context"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxPreferredLength = 0xFFFFFFFF
	errorMoreData      = 234
	nerrSuccess        = 0
)

var (
	modNetapi32                   = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupEnum         = modNetapi32.NewProc("NetLocalGroupEnum")
	procNetLocalGroupGetMembers   = modNetapi32.NewProc("NetLocalGroupGetMembers")
	procNetApiBufferFreeUserGroup = modNetapi32.NewProc("NetApiBufferFree")
)

type localGroupInfo1 struct {
	Name    *uint16
	Comment *uint16
}

type localGroupMembersInfo2 struct {
	SID           *windows.SID
	SidUsage      uint32
	DomainAndName *uint16
}

type windowsGroup struct {
	Name        string
	Description string
}

type windowsGroupAPI interface {
	EnumLocalGroups() ([]windowsGroup, error)
	GroupMembers(name string) ([]GroupMember, error)
}

type netLocalGroupAPI struct{}

var windowsGroupAPIProvider = func() windowsGroupAPI {
	return &netLocalGroupAPI{}
}

func collectUserGroups(ctx context.Context) ([]UserGroupInfo, error) {
	_ = ctx

	api := windowsGroupAPIProvider()
	groups, err := api.EnumLocalGroups()
	if err != nil {
		return nil, err
	}

	out := make([]UserGroupInfo, 0, len(groups))
	for _, group := range groups {
		members, _ := api.GroupMembers(group.Name)
		out = append(out, UserGroupInfo{
			Name:        nullableString(group.Name),
			Description: nullableString(group.Description),
			Members:     members,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		li := ""
		if out[i].Name != nil {
			li = strings.ToLower(*out[i].Name)
		}
		lj := ""
		if out[j].Name != nil {
			lj = strings.ToLower(*out[j].Name)
		}
		return li < lj
	})
	return out, nil
}

func (n *netLocalGroupAPI) EnumLocalGroups() ([]windowsGroup, error) {
	var (
		resume uintptr
		out    []windowsGroup
	)

	for {
		var (
			buf     uintptr
			entries uint32
			total   uint32
		)

		r0, _, _ := procNetLocalGroupEnum.Call(
			0,
			1,
			uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)

		if r0 != nerrSuccess && r0 != errorMoreData {
			if buf != 0 {
				_, _, _ = procNetApiBufferFreeUserGroup.Call(buf)
			}
			return nil, syscall.Errno(r0)
		}

		if buf != 0 {
			records := unsafe.Slice((*localGroupInfo1)(unsafe.Pointer(buf)), int(entries))
			for _, rec := range records {
				out = append(out, windowsGroup{
					Name:        utf16PtrToString(rec.Name),
					Description: utf16PtrToString(rec.Comment),
				})
			}
			_, _, _ = procNetApiBufferFreeUserGroup.Call(buf)
		}

		if r0 == nerrSuccess {
			break
		}
	}

	return out, nil
}

func (n *netLocalGroupAPI) GroupMembers(name string) ([]GroupMember, error) {
	groupPtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	var (
		resume uintptr
		out    []GroupMember
	)
	seen := map[string]struct{}{}

	for {
		var (
			buf     uintptr
			entries uint32
			total   uint32
		)
		r0, _, _ := procNetLocalGroupGetMembers.Call(
			0,
			uintptr(unsafe.Pointer(groupPtr)),
			2,
			uintptr(unsafe.Pointer(&buf)),
			maxPreferredLength,
			uintptr(unsafe.Pointer(&entries)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&resume)),
		)

		if r0 != nerrSuccess && r0 != errorMoreData {
			if buf != 0 {
				_, _, _ = procNetApiBufferFreeUserGroup.Call(buf)
			}
			return nil, syscall.Errno(r0)
		}

		if buf != 0 {
			records := unsafe.Slice((*localGroupMembersInfo2)(unsafe.Pointer(buf)), int(entries))
			for _, rec := range records {
				memberName := strings.TrimSpace(utf16PtrToString(rec.DomainAndName))
				if memberName == "" {
					continue
				}
				if _, ok := seen[memberName]; ok {
					continue
				}
				seen[memberName] = struct{}{}
				memberType := int(rec.SidUsage)
				out = append(out, GroupMember{
					Name: strPtr(memberName),
					Type: intPtr(memberType),
				})
			}
			_, _, _ = procNetApiBufferFreeUserGroup.Call(buf)
		}

		if r0 == nerrSuccess {
			break
		}
	}

	sort.Slice(out, func(i, j int) bool {
		li := ""
		if out[i].Name != nil {
			li = strings.ToLower(*out[i].Name)
		}
		lj := ""
		if out[j].Name != nil {
			lj = strings.ToLower(*out[j].Name)
		}
		return li < lj
	})
	return out, nil
}

func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	return windows.UTF16PtrToString(ptr)
}
