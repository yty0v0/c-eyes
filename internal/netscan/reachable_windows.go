//go:build windows

package netscan

import (
	"fmt"
	"net"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tcpTableOwnerPIDAll    = 5
	mibTCPStateEstablished = 5
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]mibTCPRowOwnerPID
}

func collectRouteCandidates() ([]reachabilitySignal, []string) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, []string{fmt.Sprintf("reachableSegments: route collector unavailable on windows: %v", err)}
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	out := make([]reachabilitySignal, 0, table.NumEntries)
	for _, row := range table.Rows() {
		cidr, ok := normalizeWindowsRouteCIDR(row.DestinationPrefix)
		if !ok {
			continue
		}
		nextHop := ""
		if ip, ok := windowsSockaddrInetToIPv4(row.NextHop); ok && isPrivateIPv4(ip) {
			nextHop = ip.String()
		}
		out = append(out, reachabilitySignal{
			CIDR:    cidr,
			NextHop: nextHop,
			Source:  "route_table",
		})
	}
	return out, nil
}

func collectConnectionCandidates() ([]reachabilitySignal, []string) {
	var size uint32
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(windows.AF_INET),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != 0 && ret != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, []string{fmt.Sprintf("reachableSegments: connection collector unavailable on windows: GetExtendedTcpTable size probe failed with code=%d", ret)}
	}
	if size < uint32(unsafe.Sizeof(mibTCPTableOwnerPID{})) {
		return []reachabilitySignal{}, nil
	}

	buffer := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(windows.AF_INET),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if ret != 0 {
		return nil, []string{fmt.Sprintf("reachableSegments: connection collector unavailable on windows: GetExtendedTcpTable failed with code=%d", ret)}
	}
	table := (*mibTCPTableOwnerPID)(unsafe.Pointer(&buffer[0]))
	if table.NumEntries == 0 {
		return []reachabilitySignal{}, nil
	}

	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	out := make([]reachabilitySignal, 0, len(rows))
	for _, row := range rows {
		if row.State != mibTCPStateEstablished {
			continue
		}
		remoteIP := uint32ToIPv4(row.RemoteAddr)
		if remoteIP == nil || !isPrivateIPv4(remoteIP) {
			continue
		}
		cidr := fmt.Sprintf("%d.%d.%d.0/24", remoteIP[0], remoteIP[1], remoteIP[2])
		out = append(out, reachabilitySignal{
			CIDR:   cidr,
			Source: "active_connections",
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return compareIPStringsCIDR(out[i].CIDR, out[j].CIDR) < 0
	})
	return out, nil
}

func normalizeWindowsRouteCIDR(prefix windows.IpAddressPrefix) (string, bool) {
	ip, ok := windowsSockaddrInetToIPv4(prefix.Prefix)
	if !ok || ip == nil || !isPrivateIPv4(ip) {
		return "", false
	}
	ones := int(prefix.PrefixLength)
	if ones <= 0 || ones > 31 {
		return "", false
	}
	mask := net.CIDRMask(ones, 32)
	network := ip.Mask(mask).To4()
	if network == nil || !isPrivateIPv4(network) {
		return "", false
	}
	return fmt.Sprintf("%s/%d", network.String(), ones), true
}

func windowsSockaddrInetToIPv4(addr windows.RawSockaddrInet) (net.IP, bool) {
	if addr.Family != windows.AF_INET {
		return nil, false
	}
	v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
	ip := net.IPv4(v4.Addr[0], v4.Addr[1], v4.Addr[2], v4.Addr[3]).To4()
	if ip == nil {
		return nil, false
	}
	return ip, true
}

func uint32ToIPv4(value uint32) net.IP {
	ip := net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).To4()
	if ip == nil || ip.Equal(net.IPv4zero) {
		return nil
	}
	return ip
}
