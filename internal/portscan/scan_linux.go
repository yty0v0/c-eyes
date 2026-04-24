//go:build linux

package portscan

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type linuxSocketRow struct {
	Proto  string
	BindIP string
	Port   int
	Inode  string
}

type procRef struct {
	PID  int
	Name string
}

func collectTCPConnectPorts(ctx context.Context) ([]PortInfo, error) {
	rows, err := collectLinuxPorts(ctx)
	if err != nil {
		return nil, err
	}
	return applyTCPConnectProbe(ctx, rows), nil
}

func collectTCPSYNPorts(ctx context.Context) ([]PortInfo, error) {
	// SYN mode keeps passive collection semantics and does not establish connections.
	return collectLinuxPorts(ctx)
}

func collectLinuxPorts(ctx context.Context) ([]PortInfo, error) {
	sockets, err := collectLinuxSockets()
	if err != nil {
		return nil, err
	}

	procs := collectProcRefs(ctx)
	rows := make([]PortInfo, 0, len(sockets))
	for _, socket := range sockets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row := PortInfo{
			Proto:  strPtr(socket.Proto),
			Port:   intPtr(socket.Port),
			BindIP: strPtr(socket.BindIP),
			Status: statusFromBindIP(socket.BindIP),
		}
		if ref, ok := procs[socket.Inode]; ok {
			row.PID = intPtr(ref.PID)
			if ref.Name != "" {
				row.ProcessName = strPtr(ref.Name)
			}
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		li := 0
		if rows[i].Port != nil {
			li = *rows[i].Port
		}
		lj := 0
		if rows[j].Port != nil {
			lj = *rows[j].Port
		}
		if li != lj {
			return li < lj
		}
		pi := ""
		if rows[i].Proto != nil {
			pi = *rows[i].Proto
		}
		pj := ""
		if rows[j].Proto != nil {
			pj = *rows[j].Proto
		}
		if pi != pj {
			return pi < pj
		}
		bi := ""
		if rows[i].BindIP != nil {
			bi = *rows[i].BindIP
		}
		bj := ""
		if rows[j].BindIP != nil {
			bj = *rows[j].BindIP
		}
		return bi < bj
	})

	return rows, nil
}

func collectLinuxSockets() ([]linuxSocketRow, error) {
	tcp4, err := parseProcNetTCP("/proc/net/tcp", "tcp")
	if err != nil {
		return nil, err
	}
	tcp6, err := parseProcNetTCP("/proc/net/tcp6", "tcp6")
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	out := make([]linuxSocketRow, 0, len(tcp4)+len(tcp6))
	out = append(out, tcp4...)
	out = append(out, tcp6...)
	return out, nil
}

func parseProcNetTCP(path, proto string) ([]linuxSocketRow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	out := make([]linuxSocketRow, 0, 64)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		// LISTEN only.
		if state != "0A" {
			continue
		}

		bindIP, port, err := parseLocalAddress(fields[1])
		if err != nil {
			continue
		}
		inode := fields[9]
		out = append(out, linuxSocketRow{
			Proto:  proto,
			BindIP: bindIP,
			Port:   port,
			Inode:  inode,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseLocalAddress(value string) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid local address")
	}

	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	ip, err := parseProcHexIP(parts[0])
	if err != nil {
		return "", 0, err
	}
	return ip, int(port64), nil
}

func parseProcHexIP(hexIP string) (string, error) {
	switch len(hexIP) {
	case 8:
		raw, err := hex.DecodeString(hexIP)
		if err != nil || len(raw) != 4 {
			return "", fmt.Errorf("invalid ipv4 hex")
		}
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), nil
	case 32:
		raw, err := hex.DecodeString(hexIP)
		if err != nil || len(raw) != 16 {
			return "", fmt.Errorf("invalid ipv6 hex")
		}
		normalized := make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			normalized[i] = raw[i+3]
			normalized[i+1] = raw[i+2]
			normalized[i+2] = raw[i+1]
			normalized[i+3] = raw[i]
		}
		return net.IP(normalized).String(), nil
	default:
		return "", fmt.Errorf("unsupported address size")
	}
}

func collectProcRefs(ctx context.Context) map[string]procRef {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return map[string]procRef{}
	}

	out := make(map[string]procRef, 1024)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return out
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		name := readProcName(pid)
		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			inode, ok := parseSocketInode(target)
			if !ok {
				continue
			}
			if _, exists := out[inode]; !exists {
				out[inode] = procRef{PID: pid, Name: name}
			}
		}
	}
	return out
}

func readProcName(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func parseSocketInode(target string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), true
}
