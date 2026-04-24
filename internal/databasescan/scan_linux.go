//go:build linux

package databasescan

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type linuxSocketRow struct {
	Proto  string
	BindIP string
	Port   int
	Inode  string
}

type linuxProcInfo struct {
	PID     int
	Name    string
	Cmdline []string
	User    string
}

func collectDatabaseRecords(ctx context.Context) ([]DatabaseRecord, error) {
	sockets, err := collectLinuxSockets()
	if err != nil {
		return nil, err
	}
	procRefs := collectLinuxProcRefs(ctx)
	procs := collectLinuxProcesses(ctx)

	rows := make([]DatabaseRecord, 0, len(sockets))
	seen := make(map[string]struct{})
	for _, socket := range sockets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		proc, ok := procRefs[socket.Inode]
		if !ok {
			continue
		}

		// Docker bridge mode commonly exposes database ports via docker-proxy.
		// In this case, the listening inode belongs to docker-proxy instead of
		// mongod/postgres in container namespaces, so we infer DB type from
		// container-port/host-port mapping.
		if strings.EqualFold(proc.Name, "docker-proxy") {
			rec, ok := buildDockerProxyRecord(proc, socket)
			if !ok {
				continue
			}
			port := 0
			if rec.Port != nil {
				port = *rec.Port
			}
			key := safeName(rec.Name) + "|" + socket.Proto + "|" + strconv.Itoa(port) + "|" + socket.BindIP
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			rows = append(rows, rec)
			continue
		}

		dbName := detectLinuxDB(proc.Name, proc.Cmdline)
		if dbName == "" {
			continue
		}
		rec := DatabaseRecord{
			Name:      strPtr(dbName),
			Port:      intPtr(socket.Port),
			ProtoType: strPtr(socket.Proto),
			BindIP:    strPtr(socket.BindIP),
			User:      nullableString(proc.User),
		}
		applyLinuxSpecialFields(&rec, dbName, proc)

		key := dbName + "|" + socket.Proto + "|" + strconv.Itoa(socket.Port) + "|" + socket.BindIP
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		rows = append(rows, rec)
	}

	// Fallback for environments where /proc/<pid>/fd is restricted for
	// non-root users (common on hardened/Kali setups). We can still infer
	// database exposure from docker-proxy command lines.
	for _, proc := range procs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.EqualFold(proc.Name, "docker-proxy") {
			continue
		}
		socket, ok := buildDockerProxySocket(proc)
		if !ok {
			continue
		}
		rec, ok := buildDockerProxyRecord(proc, socket)
		if !ok {
			continue
		}
		port := 0
		if rec.Port != nil {
			port = *rec.Port
		}
		key := safeName(rec.Name) + "|" + safeName(rec.ProtoType) + "|" + strconv.Itoa(port) + "|" + safeName(rec.BindIP)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		rows = append(rows, rec)
	}

	sort.Slice(rows, func(i, j int) bool {
		ni := ""
		nj := ""
		if rows[i].Name != nil {
			ni = *rows[i].Name
		}
		if rows[j].Name != nil {
			nj = *rows[j].Name
		}
		if ni != nj {
			return ni < nj
		}
		pi := 0
		pj := 0
		if rows[i].Port != nil {
			pi = *rows[i].Port
		}
		if rows[j].Port != nil {
			pj = *rows[j].Port
		}
		return pi < pj
	})
	return rows, nil
}

func collectLinuxSockets() ([]linuxSocketRow, error) {
	tcp4, err := parseProcNetTCP("/proc/net/tcp", "tcp")
	if err != nil {
		return nil, err
	}
	tcp6, err := parseProcNetTCP("/proc/net/tcp6", "tcp6")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
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
		if fields[3] != "0A" {
			continue
		}
		bindIP, port, err := parseLocalAddress(fields[1])
		if err != nil {
			continue
		}
		out = append(out, linuxSocketRow{
			Proto:  proto,
			BindIP: bindIP,
			Port:   port,
			Inode:  fields[9],
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

func collectLinuxProcRefs(ctx context.Context) map[string]linuxProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return map[string]linuxProcInfo{}
	}
	out := make(map[string]linuxProcInfo, 1024)
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
		proc := linuxProcInfo{
			PID:     pid,
			Name:    readProcName(pid),
			Cmdline: readProcCmdline(pid),
			User:    readProcUser(pid),
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
			inode, ok := parseSocketInode(target)
			if !ok {
				continue
			}
			if _, exists := out[inode]; !exists {
				out[inode] = proc
			}
		}
	}
	return out
}

func collectLinuxProcesses(ctx context.Context) []linuxProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	out := make([]linuxProcInfo, 0, 256)
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
		proc := linuxProcInfo{
			PID:     pid,
			Name:    readProcName(pid),
			Cmdline: readProcCmdline(pid),
			User:    readProcUser(pid),
		}
		if proc.Name == "" && len(proc.Cmdline) == 0 {
			continue
		}
		out = append(out, proc)
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

func readProcCmdline(pid int) []string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	raw := strings.Split(string(data), "\x00")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func readProcUser(pid int) string {
	info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	u, err := user.LookupId(strconv.Itoa(int(stat.Uid)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Username)
}

func parseSocketInode(target string) (string, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, prefix), "]"), true
}

func detectLinuxDB(procName string, cmdline []string) string {
	full := strings.ToLower(strings.Join(cmdline, " "))
	name := strings.ToLower(procName)
	switch {
	case strings.Contains(name, "mysqld") || strings.Contains(full, "mysqld"):
		return "MySQL"
	case name == "postgres" || name == "postmaster" || strings.Contains(full, "/postgres ") || strings.Contains(full, " postmaster "):
		return "PostgreSQL"
	case strings.Contains(name, "mongod") || strings.Contains(full, "mongod"):
		return "MongoDB"
	case strings.Contains(name, "hbase") || strings.Contains(full, "hbase"):
		return "HBase"
	case strings.Contains(name, "tnslsnr") || strings.Contains(full, "tnslsnr"):
		return "Oracle"
	case strings.Contains(name, "sqlservr") || strings.Contains(full, "sqlservr"):
		return "SQL Server"
	default:
		return ""
	}
}

func safeName(name *string) string {
	if name == nil {
		return ""
	}
	return *name
}

func buildDockerProxyRecord(proc linuxProcInfo, socket linuxSocketRow) (DatabaseRecord, bool) {
	hostPort, ok := parseIntArg(proc.Cmdline, "-host-port")
	if !ok {
		return DatabaseRecord{}, false
	}
	containerPort, hasContainerPort := parseIntArg(proc.Cmdline, "-container-port")

	dbName := detectDBByPort(containerPort)
	if dbName == "" {
		dbName = detectDBByPort(hostPort)
	}
	if dbName == "" {
		return DatabaseRecord{}, false
	}

	rec := DatabaseRecord{
		Name:      strPtr(dbName),
		Port:      intPtr(hostPort),
		ProtoType: strPtr(socket.Proto),
		BindIP:    strPtr(socket.BindIP),
		User:      nullableString(proc.User),
	}

	// Keep extra context for docker-proxy rows.
	containerIP := extractArgValue(proc.Cmdline, "-container-ip")
	if hasContainerPort && containerIP != "" {
		rec.DBName = nullableString(containerIP + ":" + strconv.Itoa(containerPort))
	}
	return rec, true
}

func parseIntArg(args []string, keys ...string) (int, bool) {
	v := extractArgValue(args, keys...)
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, false
	}
	return n, true
}

func detectDBByPort(port int) string {
	switch port {
	case 27017:
		return "MongoDB"
	case 5432, 5433:
		return "PostgreSQL"
	case 3306:
		return "MySQL"
	case 1433:
		return "SQL Server"
	case 1521:
		return "Oracle"
	default:
		return ""
	}
}

func buildDockerProxySocket(proc linuxProcInfo) (linuxSocketRow, bool) {
	hostPort, ok := parseIntArg(proc.Cmdline, "-host-port")
	if !ok {
		return linuxSocketRow{}, false
	}
	proto := extractArgValue(proc.Cmdline, "-proto")
	if proto == "" {
		proto = "tcp"
	}
	bindIP := extractArgValue(proc.Cmdline, "-host-ip")
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	return linuxSocketRow{
		Proto:  proto,
		BindIP: bindIP,
		Port:   hostPort,
	}, true
}

func applyLinuxSpecialFields(rec *DatabaseRecord, dbName string, proc linuxProcInfo) {
	conf := extractArgValue(proc.Cmdline, "--defaults-file", "--config", "-f")
	dataDir := extractArgValue(proc.Cmdline, "--datadir", "--dbpath")
	logPath := extractArgValue(proc.Cmdline, "--log-error", "--logpath")
	rec.ConfPath = nullableString(conf)
	rec.DataDir = nullableString(dataDir)
	rec.LogPath = nullableString(logPath)

	switch normalizeDBName(dbName) {
	case "mysql":
		rec.PluginDir = nullableString(extractArgValue(proc.Cmdline, "--plugin-dir"))
	case "postgresql":
		// postgres commonly uses `-D <data_dir>` and optional `-c config_file=...`
		if rec.DataDir == nil {
			rec.DataDir = nullableString(extractArgValue(proc.Cmdline, "-D"))
		}
		if rec.ConfPath == nil {
			if cfgKV := extractArgValue(proc.Cmdline, "-c"); cfgKV != "" {
				if strings.HasPrefix(strings.ToLower(cfgKV), "config_file=") {
					rec.ConfPath = nullableString(strings.Trim(strings.TrimPrefix(cfgKV, "config_file="), `"`))
				}
			}
		}
	case "mongodb":
		rec.Rest = boolPtr(hasArg(proc.Cmdline, "--rest"))
		if hasArg(proc.Cmdline, "--noauth") {
			rec.Auth = strPtr("disabled")
		} else if hasArg(proc.Cmdline, "--auth") {
			rec.Auth = strPtr("enabled")
		}
		webEnabled := hasArg(proc.Cmdline, "--httpinterface") || hasArg(proc.Cmdline, "--rest")
		if hasArg(proc.Cmdline, "--nohttpinterface") {
			webEnabled = false
		}
		rec.Web = boolPtr(webEnabled)
	case "hbase":
		if confPath := pickFirst(conf, "/etc/hbase/conf/hbase-site.xml", "/opt/hbase/conf/hbase-site.xml"); confPath != nil {
			rec.ConfPath = confPath
			webPort, webAddr, regionServers := parseHBaseSite(*confPath)
			if webPort > 0 {
				rec.WebPort = intPtr(webPort)
			}
			rec.WebAddress = nullableString(webAddr)
			if len(regionServers) > 0 {
				rec.RegionServer = regionServers
			}
		}
	case "oracle":
		if rec.WebAddress == nil {
			rec.WebAddress = nullableString(extractArgValue(proc.Cmdline, "--address"))
		}
	}
}

type hbaseSite struct {
	Properties []struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"property"`
}

func parseHBaseSite(path string) (int, string, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", nil
	}
	var cfg hbaseSite
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return 0, "", nil
	}
	var (
		webPort int
		webAddr string
		region  []string
	)
	for _, item := range cfg.Properties {
		key := strings.ToLower(strings.TrimSpace(item.Name))
		val := strings.TrimSpace(item.Value)
		switch key {
		case "hbase.master.info.port":
			if p, err := strconv.Atoi(val); err == nil {
				webPort = p
			}
		case "hbase.master.info.bindaddress":
			webAddr = val
		case "hbase.regionserver.hostname":
			if val != "" {
				region = append(region, val)
			}
		}
	}
	return webPort, webAddr, region
}
