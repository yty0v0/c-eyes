package processscan

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
)

// GetHostInfo collects host metadata and applies optional config overrides.
// 获取主机名、IP 列表，并按优先级填充 DisplayIP，再读取可选配置并覆盖字段
func GetHostInfo() (HostInfo, error) {
	hostname, _ := os.Hostname()
	ips, internals, externals := collectIPs()

	host := HostInfo{
		Hostname:    hostname,
		IPs:         ips,
		InternalIPs: internals,
		ExternalIPs: externals,
	}
	if len(host.ExternalIPs) > 0 {
		host.DisplayIP = strPtr(host.ExternalIPs[0])
	} else if len(host.InternalIPs) > 0 {
		host.DisplayIP = strPtr(host.InternalIPs[0])
	}

	cfg, _ := loadConfig()
	if cfg != nil {
		if cfg.DisplayIP != nil {
			host.DisplayIP = cfg.DisplayIP
		}
		for _, ip := range cfg.ExternalIPList {
			if ip == "" {
				continue
			}
			host.ExternalIPs = appendUniqueIP(host.ExternalIPs, ip)
		}
		for _, ip := range cfg.InternalIPList {
			if ip == "" {
				continue
			}
			host.InternalIPs = appendUniqueIP(host.InternalIPs, ip)
		}
		if cfg.BizGroupID != nil {
			host.BizGroupID = cfg.BizGroupID
		}
		if cfg.BizGroup != nil {
			host.BizGroup = cfg.BizGroup
		}
		if cfg.Remark != nil {
			host.Remark = cfg.Remark
		}
		if cfg.HostTagList != nil {
			host.HostTagList = cfg.HostTagList
		}
	}
	if host.DisplayIP == nil {
		if len(host.ExternalIPs) > 0 {
			host.DisplayIP = strPtr(host.ExternalIPs[0])
		} else if len(host.InternalIPs) > 0 {
			host.DisplayIP = strPtr(host.InternalIPs[0])
		}
	}

	return host, nil
}

// 遍历网卡地址，过滤掉回环和 IPv6，只保留 IPv4；区分内网/外网 IP
func collectIPs() ([]string, []string, []string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, nil
	}

	var ips []string
	var internalIPs []string
	var externalIPs []string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := extractIP(addr)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			ipStr := ipv4.String()
			ips = appendUniqueIP(ips, ipStr)
			if isPrivateIP(ipv4) {
				internalIPs = appendUniqueIP(internalIPs, ipStr)
			} else {
				externalIPs = appendUniqueIP(externalIPs, ipStr)
			}
		}
	}

	if len(internalIPs) == 0 && len(ips) > 0 {
		internalIPs = append(internalIPs, ips[0])
	}

	return ips, internalIPs, externalIPs
}

// net.Addr 里抽取 net.IP
func extractIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// 判断 IPv4 是否属于内网段
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// IPv4 private ranges
	if ip[0] == 10 {
		return true
	}
	if ip[0] == 172 && ip[1]&0xf0 == 16 {
		return true
	}
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}
	return false
}

func appendUniqueIP(list []string, ip string) []string {
	for _, item := range list {
		if item == ip {
			return list
		}
	}
	return append(list, ip)
}

// 读取 JSON 配置文件
func loadConfig() (*Config, error) {
	path := os.Getenv("C_EYES_CONFIG")
	if path == "" {
		if _, err := os.Stat("c-eyes-config.json"); err == nil {
			path = "c-eyes-config.json"
		} else {
			home, err := os.UserHomeDir()
			if err == nil {
				candidate := filepath.Join(home, ".c-eyes", "config.json")
				if _, err := os.Stat(candidate); err == nil {
					path = candidate
				}
			}
		}
	}

	if path == "" {
		return nil, errors.New("config not found")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
