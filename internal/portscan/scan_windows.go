//go:build windows

package portscan

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	afINET              = 2
	afINET6             = 23
	tcpTableOwnerPIDAll = 5
	mibTCPStateListen   = 2
	tcpTableBasicOrder  = 0
	errorInsufficentBuf = 122
	defaultTableBufSize = 16 * 1024
)

var (
	modIPHLPAPI          = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTable = modIPHLPAPI.NewProc("GetExtendedTcpTable")
)

type windowsPortCollector interface {
	Collect() ([]PortInfo, error)
}

type nativeWindowsPortCollector struct{}

var windowsPortCollectorProvider = func() windowsPortCollector {
	return &nativeWindowsPortCollector{}
}

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibTCP6RowOwnerPID struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	RemoteAddr   [16]byte
	RemoteScope  uint32
	RemotePort   uint32
	State        uint32
	OwningPID    uint32
}

func collectTCPConnectPorts(ctx context.Context) ([]PortInfo, error) {
	rows, err := windowsPortCollectorProvider().Collect()
	if err != nil {
		return nil, err
	}
	return applyTCPConnectProbe(ctx, rows), nil
}

func collectTCPSYNPorts(ctx context.Context) ([]PortInfo, error) {
	_ = ctx
	// SYN mode keeps passive collection semantics and does not establish connections.
	return windowsPortCollectorProvider().Collect()
}

func (n *nativeWindowsPortCollector) Collect() ([]PortInfo, error) {
	tcp4, err := queryTCPv4Rows()
	if err != nil {
		return nil, err
	}
	tcp6, err := queryTCPv6Rows()
	if err != nil {
		return nil, err
	}

	out := make([]PortInfo, 0, len(tcp4)+len(tcp6))
	out = append(out, tcp4...)
	out = append(out, tcp6...)
	sort.Slice(out, func(i, j int) bool {
		li := 0
		if out[i].Port != nil {
			li = *out[i].Port
		}
		lj := 0
		if out[j].Port != nil {
			lj = *out[j].Port
		}
		if li != lj {
			return li < lj
		}
		pi := ""
		if out[i].Proto != nil {
			pi = *out[i].Proto
		}
		pj := ""
		if out[j].Proto != nil {
			pj = *out[j].Proto
		}
		if pi != pj {
			return pi < pj
		}
		bi := ""
		if out[i].BindIP != nil {
			bi = *out[i].BindIP
		}
		bj := ""
		if out[j].BindIP != nil {
			bj = *out[j].BindIP
		}
		return bi < bj
	})
	return out, nil
}

func queryTCPv4Rows() ([]PortInfo, error) {
	buf, err := queryExtendedTable(afINET)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return []PortInfo{}, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	if total == 0 {
		return []PortInfo{}, nil
	}

	rows := make([]PortInfo, 0, total)
	rowSize := int(unsafe.Sizeof(mibTCPRowOwnerPID{}))
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	for i := 0; i < total; i++ {
		rowPtr := unsafe.Pointer(base + uintptr(i*rowSize))
		row := *(*mibTCPRowOwnerPID)(rowPtr)
		if row.State != mibTCPStateListen {
			continue
		}
		bindIP := ipv4FromUint32(row.LocalAddr)
		port := portFromDWORD(row.LocalPort)
		pid := int(row.OwningPID)
		proc := processNameByPID(row.OwningPID)
		entry := PortInfo{
			Proto:  strPtr("tcp"),
			Port:   intPtr(port),
			BindIP: strPtr(bindIP),
			PID:    intPtr(pid),
			Status: statusFromBindIP(bindIP),
		}
		if proc != "" {
			entry.ProcessName = strPtr(proc)
		}
		rows = append(rows, entry)
	}
	return rows, nil
}

func queryTCPv6Rows() ([]PortInfo, error) {
	buf, err := queryExtendedTable(afINET6)
	if err != nil {
		return nil, err
	}
	if len(buf) < 4 {
		return []PortInfo{}, nil
	}
	total := int(*(*uint32)(unsafe.Pointer(&buf[0])))
	if total == 0 {
		return []PortInfo{}, nil
	}

	rows := make([]PortInfo, 0, total)
	rowSize := int(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
	base := uintptr(unsafe.Pointer(&buf[0])) + unsafe.Sizeof(uint32(0))
	for i := 0; i < total; i++ {
		rowPtr := unsafe.Pointer(base + uintptr(i*rowSize))
		row := *(*mibTCP6RowOwnerPID)(rowPtr)
		if row.State != mibTCPStateListen {
			continue
		}
		bindIP := net.IP(row.LocalAddr[:]).String()
		port := portFromDWORD(row.LocalPort)
		pid := int(row.OwningPID)
		proc := processNameByPID(row.OwningPID)
		entry := PortInfo{
			Proto:  strPtr("tcp6"),
			Port:   intPtr(port),
			BindIP: strPtr(bindIP),
			PID:    intPtr(pid),
			Status: statusFromBindIP(bindIP),
		}
		if proc != "" {
			entry.ProcessName = strPtr(proc)
		}
		rows = append(rows, entry)
	}
	return rows, nil
}

func queryExtendedTable(af uint32) ([]byte, error) {
	size := uint32(defaultTableBufSize)
	buf := make([]byte, size)

	r0, _, _ := procGetExtendedTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		tcpTableBasicOrder,
		uintptr(af),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)
	if windows.Errno(r0) == windows.ERROR_INSUFFICIENT_BUFFER || windows.Errno(r0) == windows.Errno(errorInsufficentBuf) {
		buf = make([]byte, size)
		r0, _, _ = procGetExtendedTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			tcpTableBasicOrder,
			uintptr(af),
			uintptr(tcpTableOwnerPIDAll),
			0,
		)
	}
	if r0 != 0 {
		return nil, windows.Errno(r0)
	}
	return buf[:size], nil
}

func ipv4FromUint32(v uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func portFromDWORD(v uint32) int {
	return int(binary.BigEndian.Uint16([]byte{byte((v >> 8) & 0xff), byte(v & 0xff)}))
}

func processNameByPID(pid uint32) string {
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
	base := filepath.Base(fullPath)
	base = strings.TrimSpace(base)
	if base != "" {
		return base
	}
	return fullPath
}
