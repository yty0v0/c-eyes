package portscan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

const tcpConnectProbeTimeout = 200 * time.Millisecond

func applyTCPConnectProbe(ctx context.Context, rows []PortInfo) []PortInfo {
	out := make([]PortInfo, 0, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			out = append(out, row)
			continue
		}

		probed := row
		if row.BindIP == nil || row.Port == nil || row.Proto == nil {
			if probed.Status == nil {
				probed.Status = intPtr(-1)
			}
			out = append(out, probed)
			continue
		}

		reachable := false
		for _, target := range probeTargets(*row.BindIP) {
			dialer := net.Dialer{Timeout: tcpConnectProbeTimeout}
			address := net.JoinHostPort(target, strconv.Itoa(*row.Port))
			conn, err := dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				continue
			}
			_ = conn.Close()
			reachable = true
			break
		}

		if reachable {
			probed.Status = statusFromBindIP(*row.BindIP)
		} else if probed.Status == nil {
			probed.Status = intPtr(-1)
		}
		out = append(out, probed)
	}
	return out
}

func probeTargets(bindIP string) []string {
	trimmed := strings.TrimSpace(bindIP)
	if trimmed == "" {
		return nil
	}
	switch trimmed {
	case "0.0.0.0":
		return []string{"127.0.0.1"}
	case "::", "*":
		return []string{"::1", "127.0.0.1"}
	default:
		return []string{trimmed}
	}
}
