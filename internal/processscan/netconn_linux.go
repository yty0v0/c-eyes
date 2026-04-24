//go:build linux

package processscan

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type procNetRemoteRow struct {
	Inode    string
	RemoteIP string
}

func collectProcessExternalIPs(ctx context.Context) (map[int][]string, error) {
	inodeToExternalIPs, err := collectLinuxExternalSocketInodes()
	if err != nil {
		return nil, err
	}
	if len(inodeToExternalIPs) == 0 {
		return map[int][]string{}, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	out := make(map[int][]string, 256)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseProcSocketInode(target)
			if !ok {
				continue
			}
			ips, ok := inodeToExternalIPs[inode]
			if !ok {
				continue
			}
			for _, ip := range ips {
				mergeProcessExternalIP(out, pid, ip)
			}
		}
	}
	normalizeProcessExternalIPMap(out)
	return out, nil
}

func collectLinuxExternalSocketInodes() (map[string][]string, error) {
	out := make(map[string][]string, 256)
	collect := func(path string, tcp bool) error {
		rows, err := parseProcNetRemoteFile(path, tcp)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		for _, row := range rows {
			current := out[row.Inode]
			updated := appendUniqueIP(current, row.RemoteIP)
			out[row.Inode] = updated
		}
		return nil
	}

	if err := collect("/proc/net/tcp", true); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/tcp6", true); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/udp", false); err != nil {
		return nil, err
	}
	if err := collect("/proc/net/udp6", false); err != nil {
		return nil, err
	}
	return out, nil
}

func parseProcNetRemoteFile(path string, tcp bool) ([]procNetRemoteRow, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	rows := make([]procNetRemoteRow, 0, 64)
	first := true
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
		if tcp && state == "0A" {
			// LISTEN has no remote peer.
			continue
		}
		remoteIP, remotePort, err := parseProcHexAddress(fields[2])
		if err != nil || remotePort == 0 {
			continue
		}
		if !isExternalRemoteIP(remoteIP) {
			continue
		}
		inode := fields[9]
		if inode == "" || inode == "0" {
			continue
		}
		rows = append(rows, procNetRemoteRow{Inode: inode, RemoteIP: remoteIP})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func parseProcHexAddress(value string) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address")
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

func parseProcSocketInode(target string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), true
}
