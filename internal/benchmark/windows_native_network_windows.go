//go:build windows

package benchmark

import (
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	benchmarkAFInet                  = 2
	benchmarkAFInet6                 = 23
	benchmarkTCPTableOwnerPIDAll     = 5
	benchmarkUDPTableOwnerPID        = 1
	benchmarkTCPTableClassBasicOrder = 0
	benchmarkTableDefaultBufSize     = 16 * 1024
	benchmarkErrorInsufficientBuf    = 122
)

var (
	modIPHLPAPIBenchmark       = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTableBmk = modIPHLPAPIBenchmark.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTableBmk = modIPHLPAPIBenchmark.NewProc("GetExtendedUdpTable")
)

type windowsNetConnection struct {
	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    int    `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
	PID           uint32 `json:"pid,omitempty"`
	ProcessName   string `json:"process_name,omitempty"`
}

type benchmarkMibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type benchmarkMibTCP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	RemoteAddr   [16]byte
	RemoteScope  uint32
	RemotePort   uint32
	State        uint32
	OwningPID    uint32
}

type benchmarkMibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

type benchmarkMibUDP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	OwningPID    uint32
}

func collectWindowsNetConnections() ([]windowsNetConnection, error) {
	rows := make([]windowsNetConnection, 0, 256)

	tcp4, err := queryBenchmarkTCPv4()
	if err != nil {
		return nil, err
	}
	rows = append(rows, tcp4...)

	tcp6, err := queryBenchmarkTCPv6()
	if err != nil {
		return nil, err
	}
	rows = append(rows, tcp6...)

	udp4, err := queryBenchmarkUDPv4()
	if err != nil {
		return nil, err
	}
	rows = append(rows, udp4...)

	udp6, err := queryBenchmarkUDPv6()
	if err != nil {
		return nil, err
	}
	rows = append(rows, udp6...)

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Protocol != rows[j].Protocol {
			return rows[i].Protocol < rows[j].Protocol
		}
		if rows[i].LocalAddress != rows[j].LocalAddress {
			return rows[i].LocalAddress < rows[j].LocalAddress
		}
		if rows[i].LocalPort != rows[j].LocalPort {
			return rows[i].LocalPort < rows[j].LocalPort
		}
		if rows[i].RemoteAddress != rows[j].RemoteAddress {
			return rows[i].RemoteAddress < rows[j].RemoteAddress
		}
		return rows[i].RemotePort < rows[j].RemotePort
	})
	return rows, nil
}

func queryBenchmarkTCPv4() ([]windowsNetConnection, error) {
	buf, err := queryBenchmarkTable(procGetExtendedTCPTableBmk, benchmarkAFInet, benchmarkTCPTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	out := make([]windowsNetConnection, 0, total)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	rowSize := int(unsafe.Sizeof(benchmarkMibTCPRowOwnerPID{}))
	for i := 0; i < total; i++ {
		row := *(*benchmarkMibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		out = append(out, windowsNetConnection{
			Protocol:      "tcp",
			LocalAddress:  benchmarkIPv4FromUint32(row.LocalAddr),
			LocalPort:     benchmarkPortFromDWORD(row.LocalPort),
			RemoteAddress: benchmarkIPv4FromUint32(row.RemoteAddr),
			RemotePort:    benchmarkPortFromDWORD(row.RemotePort),
			State:         benchmarkTCPStateName(row.State),
			PID:           row.OwningPID,
			ProcessName:   benchmarkProcessName(row.OwningPID),
		})
	}
	return out, nil
}

func queryBenchmarkTCPv6() ([]windowsNetConnection, error) {
	buf, err := queryBenchmarkTable(procGetExtendedTCPTableBmk, benchmarkAFInet6, benchmarkTCPTableOwnerPIDAll)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	out := make([]windowsNetConnection, 0, total)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	rowSize := int(unsafe.Sizeof(benchmarkMibTCP6RowOwnerPID{}))
	for i := 0; i < total; i++ {
		row := *(*benchmarkMibTCP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		out = append(out, windowsNetConnection{
			Protocol:      "tcp6",
			LocalAddress:  net.IP(row.LocalAddr[:]).String(),
			LocalPort:     benchmarkPortFromDWORD(row.LocalPort),
			RemoteAddress: net.IP(row.RemoteAddr[:]).String(),
			RemotePort:    benchmarkPortFromDWORD(row.RemotePort),
			State:         benchmarkTCPStateName(row.State),
			PID:           row.OwningPID,
			ProcessName:   benchmarkProcessName(row.OwningPID),
		})
	}
	return out, nil
}

func queryBenchmarkUDPv4() ([]windowsNetConnection, error) {
	buf, err := queryBenchmarkTable(procGetExtendedUDPTableBmk, benchmarkAFInet, benchmarkUDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	out := make([]windowsNetConnection, 0, total)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	rowSize := int(unsafe.Sizeof(benchmarkMibUDPRowOwnerPID{}))
	for i := 0; i < total; i++ {
		row := *(*benchmarkMibUDPRowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		out = append(out, windowsNetConnection{
			Protocol:     "udp",
			LocalAddress: benchmarkIPv4FromUint32(row.LocalAddr),
			LocalPort:    benchmarkPortFromDWORD(row.LocalPort),
			State:        "LISTEN",
			PID:          row.OwningPID,
			ProcessName:  benchmarkProcessName(row.OwningPID),
		})
	}
	return out, nil
}

func queryBenchmarkUDPv6() ([]windowsNetConnection, error) {
	buf, err := queryBenchmarkTable(procGetExtendedUDPTableBmk, benchmarkAFInet6, benchmarkUDPTableOwnerPID)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return nil, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	out := make([]windowsNetConnection, 0, total)
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	rowSize := int(unsafe.Sizeof(benchmarkMibUDP6RowOwnerPID{}))
	for i := 0; i < total; i++ {
		row := *(*benchmarkMibUDP6RowOwnerPID)(unsafe.Pointer(base + uintptr(i*rowSize)))
		out = append(out, windowsNetConnection{
			Protocol:     "udp6",
			LocalAddress: net.IP(row.LocalAddr[:]).String(),
			LocalPort:    benchmarkPortFromDWORD(row.LocalPort),
			State:        "LISTEN",
			PID:          row.OwningPID,
			ProcessName:  benchmarkProcessName(row.OwningPID),
		})
	}
	return out, nil
}

func queryBenchmarkTable(proc *windows.LazyProc, addressFamily uint32, tableClass uint32) ([]byte, error) {
	size := uint32(benchmarkTableDefaultBufSize)
	buf := make([]byte, size)

	r0, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		benchmarkTCPTableClassBasicOrder,
		uintptr(addressFamily),
		uintptr(tableClass),
		0,
	)
	if windows.Errno(r0) == windows.ERROR_INSUFFICIENT_BUFFER || windows.Errno(r0) == windows.Errno(benchmarkErrorInsufficientBuf) {
		buf = make([]byte, size)
		r0, _, _ = proc.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			benchmarkTCPTableClassBasicOrder,
			uintptr(addressFamily),
			uintptr(tableClass),
			0,
		)
	}
	if r0 != 0 {
		return nil, windows.Errno(r0)
	}
	return buf[:size], nil
}

func benchmarkIPv4FromUint32(value uint32) string {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	return net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
}

func benchmarkPortFromDWORD(value uint32) int {
	return int(binary.BigEndian.Uint16([]byte{byte(value & 0xff), byte((value >> 8) & 0xff)}))
}

func benchmarkProcessName(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	fullPath := windows.UTF16ToString(buf[:size])
	if fullPath == "" {
		return ""
	}
	return filepath.Base(fullPath)
}

func benchmarkTCPStateName(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTENING"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RECEIVED"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT_1"
	case 7:
		return "FIN_WAIT_2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}
