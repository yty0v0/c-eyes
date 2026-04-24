//go:build windows

package processscan

import (
	"context"
	"encoding/binary"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processConnAFInet              = 2
	processConnAFInet6             = 23
	processConnTCPTableOwnerPIDAll = 5
	processConnTCPTableBasicOrder  = 0
	processConnMibTCPStateListen   = 2
	processConnDefaultTableBufSize = 16 * 1024
	processConnErrorInsufficient   = 122
)

var (
	modIphlpapiProcessConn     = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPForConns = modIphlpapiProcessConn.NewProc("GetExtendedTcpTable")
)

type processConnTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type processConnTCP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	RemoteAddr   [16]byte
	RemoteScope  uint32
	RemotePort   uint32
	State        uint32
	OwningPID    uint32
}

func collectProcessExternalIPs(ctx context.Context) (map[int][]string, error) {
	_ = ctx

	out := make(map[int][]string, 128)
	if err := collectWindowsExternalTCPv4(out); err != nil {
		return nil, err
	}
	if err := collectWindowsExternalTCPv6(out); err != nil {
		return nil, err
	}
	normalizeProcessExternalIPMap(out)
	return out, nil
}

func collectWindowsExternalTCPv4(out map[int][]string) error {
	buf, err := queryWindowsProcessConnTable(processConnAFInet)
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return nil
	}

	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	if total == 0 {
		return nil
	}
	rowSize := int(unsafe.Sizeof(processConnTCPRowOwnerPID{}))
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	for i := 0; i < total; i++ {
		row := *(*processConnTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		if row.State == processConnMibTCPStateListen {
			continue
		}
		if processConnPortFromDWORD(row.RemotePort) == 0 {
			continue
		}
		remoteIP := processConnIPv4FromUint32(row.RemoteAddr)
		if !isExternalRemoteIP(remoteIP) {
			continue
		}
		mergeProcessExternalIP(out, int(row.OwningPID), remoteIP)
	}
	return nil
}

func collectWindowsExternalTCPv6(out map[int][]string) error {
	buf, err := queryWindowsProcessConnTable(processConnAFInet6)
	if err != nil {
		return err
	}
	if len(buf) < 4 {
		return nil
	}

	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	if total == 0 {
		return nil
	}
	rowSize := int(unsafe.Sizeof(processConnTCP6RowOwnerPID{}))
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	for i := 0; i < total; i++ {
		row := *(*processConnTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		if row.State == processConnMibTCPStateListen {
			continue
		}
		if processConnPortFromDWORD(row.RemotePort) == 0 {
			continue
		}
		remoteIP := net.IP(row.RemoteAddr[:]).String()
		if !isExternalRemoteIP(remoteIP) {
			continue
		}
		mergeProcessExternalIP(out, int(row.OwningPID), remoteIP)
	}
	return nil
}

func queryWindowsProcessConnTable(addressFamily uint32) ([]byte, error) {
	size := uint32(processConnDefaultTableBufSize)
	buf := make([]byte, size)

	r0, _, _ := procGetExtendedTCPForConns.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		processConnTCPTableBasicOrder,
		uintptr(addressFamily),
		uintptr(processConnTCPTableOwnerPIDAll),
		0,
	)
	if windows.Errno(r0) == windows.ERROR_INSUFFICIENT_BUFFER || windows.Errno(r0) == windows.Errno(processConnErrorInsufficient) {
		buf = make([]byte, size)
		r0, _, _ = procGetExtendedTCPForConns.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			processConnTCPTableBasicOrder,
			uintptr(addressFamily),
			uintptr(processConnTCPTableOwnerPIDAll),
			0,
		)
	}
	if r0 != 0 {
		return nil, windows.Errno(r0)
	}
	return buf[:size], nil
}

func processConnIPv4FromUint32(value uint32) string {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	return net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
}

func processConnPortFromDWORD(value uint32) int {
	return int(binary.BigEndian.Uint16([]byte{byte((value >> 8) & 0xff), byte(value & 0xff)}))
}
