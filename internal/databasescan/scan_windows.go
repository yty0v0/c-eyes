//go:build windows

package databasescan

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func collectDatabaseRecords(ctx context.Context) ([]DatabaseRecord, error) {
	rows := make([]DatabaseRecord, 0)
	seen := make(map[string]struct{})

	services, _ := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if services != 0 {
		defer services.Close()
		names, _ := services.ReadSubKeyNames(-1)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			svc, err := registry.OpenKey(services, name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			imagePath, _, _ := svc.GetStringValue("ImagePath")
			runUser, _, _ := svc.GetStringValue("ObjectName")
			svc.Close()

			dbName := detectWindowsDB(name, imagePath)
			if dbName == "" {
				continue
			}
			args := parseCommandLine(imagePath)
			record := DatabaseRecord{
				Name: strPtr(dbName),
				User: nullableString(runUser),
			}
			applyWindowsSpecialFields(&record, dbName, name, imagePath, args)
			if record.Port == nil {
				record.Port = parsePortFromArgs(args)
			}
			if normalizeDBName(dbName) == "mysql" && record.Port == nil {
				record.Port = parseMySQLPortFromConfig(record.ConfPath)
			}
			key := normalizeDBName(dbName) + "|" + strconv.Itoa(valueOrZero(record.Port)) + "|" + name
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			rows = append(rows, record)
		}
	}

	appendSQLServerRegistryRows(&rows)
	return rows, nil
}

func detectWindowsDB(serviceName, imagePath string) string {
	target := strings.ToLower(serviceName + " " + imagePath)
	exe := strings.ToLower(filepath.Base(firstArg(parseCommandLine(imagePath))))
	switch {
	case strings.Contains(target, "mysqld") || strings.Contains(target, "mysql"), exe == "mysqld.exe":
		return "MySQL"
	case strings.Contains(target, "mongod") || strings.Contains(target, "mongodb"), exe == "mongod.exe":
		return "MongoDB"
	case strings.Contains(target, "hbase"):
		return "HBase"
	case strings.Contains(strings.ToLower(serviceName), "oracleservice"),
		strings.Contains(strings.ToLower(serviceName), "tnslistener"),
		strings.Contains(target, "tnslsnr"),
		exe == "tnslsnr.exe":
		return "Oracle"
	case strings.Contains(target, "mssql") || strings.Contains(target, "sqlservr") || strings.Contains(strings.ToLower(serviceName), "sql server"), exe == "sqlservr.exe":
		return "SQL Server"
	default:
		return ""
	}
}

func parseCommandLine(imagePath string) []string {
	if strings.TrimSpace(imagePath) == "" {
		return nil
	}
	parsed, err := windows.DecomposeCommandLine(imagePath)
	if err == nil && len(parsed) > 0 {
		return parsed
	}
	return strings.Fields(strings.TrimSpace(imagePath))
}

func parsePortFromArgs(args []string) *int {
	value := extractArgValue(args, "-p", "--port", "port")
	if value == "" {
		return nil
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return intPtr(port)
}

func applyWindowsSpecialFields(rec *DatabaseRecord, dbName, serviceName, imagePath string, args []string) {
	rec.ConfPath = nullableString(extractArgValue(args, "--defaults-file", "--config"))
	rec.LogPath = nullableString(extractArgValue(args, "--log-error", "--logpath", "-e"))
	rec.DataDir = nullableString(extractArgValue(args, "--datadir", "--dbpath"))
	rec.DBName = nullableString(serviceName)
	rec.Version = detectVersionFromPath(imagePath)

	switch normalizeDBName(dbName) {
	case "mysql":
		rec.PluginDir = nullableString(extractArgValue(args, "--plugin-dir"))
		if rec.ConfPath == nil {
			rec.ConfPath = detectWindowsMySQLDefaultConf(args)
		}
	case "mongodb":
		rec.Rest = boolPtr(hasArg(args, "--rest"))
		if hasArg(args, "--noauth") {
			rec.Auth = strPtr("disabled")
		} else if hasArg(args, "--auth") {
			rec.Auth = strPtr("enabled")
		}
		rec.Web = boolPtr(hasArg(args, "--httpinterface"))
	}
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.TrimSpace(args[0])
}

func detectVersionFromPath(imagePath string) *string {
	patterns := []string{
		`(?i)mysql server ([0-9]+(?:\.[0-9]+)*)`,
		`(?i)mariadb ([0-9]+(?:\.[0-9]+)*)`,
		`(?i)mongodb[\\/ ]server[\\/ ]([0-9]+(?:\.[0-9]+)*)`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(imagePath); len(m) > 1 {
			return nullableString(m[1])
		}
	}
	return nil
}

func detectWindowsMySQLDefaultConf(args []string) *string {
	exe := firstArg(args)
	if exe == "" {
		return nil
	}
	base := filepath.Dir(exe)
	candidates := []string{
		filepath.Join(base, "my.ini"),
		filepath.Join(filepath.Dir(base), "my.ini"),
		filepath.Join(filepath.Dir(filepath.Dir(base)), "my.ini"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return strPtr(p)
		}
	}
	return nil
}

func parseMySQLPortFromConfig(confPath *string) *int {
	if confPath == nil || strings.TrimSpace(*confPath) == "" {
		return nil
	}
	file, err := os.Open(*confPath)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.IndexAny(line, "#;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "port") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		v := strings.TrimSpace(parts[1])
		port, convErr := strconv.Atoi(v)
		if convErr == nil && port > 0 && port <= 65535 {
			return intPtr(port)
		}
	}
	return nil
}

func appendSQLServerRegistryRows(rows *[]DatabaseRecord) {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer`, registry.READ)
	if err != nil {
		return
	}
	defer base.Close()

	record := DatabaseRecord{
		Name: strPtr("SQL Server"),
	}
	if loginMode, _, err := base.GetIntegerValue("LoginMode"); err == nil {
		record.LoginModel = intPtr(int(loginMode))
	}
	if auditLevel, _, err := base.GetIntegerValue("AuditLevel"); err == nil {
		record.AuditLevel = intPtr(int(auditLevel))
	}
	if errLog, _, err := base.GetStringValue("ErrorLogPath"); err == nil {
		record.SysLogPath = nullableString(errLog)
	}
	if dataPath, _, err := base.GetStringValue("DefaultData"); err == nil {
		record.MainDBPath = nullableString(dataPath)
	}

	network, err := registry.OpenKey(base, `SuperSocketNetLib\Tcp`, registry.READ)
	if err == nil {
		if port, _, err := network.GetStringValue("TcpPort"); err == nil {
			if n, convErr := strconv.Atoi(strings.TrimSpace(port)); convErr == nil {
				record.Port = intPtr(n)
			}
		}
		network.Close()
	}

	if record.MainDBPath != nil && record.DataDir == nil {
		record.DataDir = record.MainDBPath
	}
	if record.DBName == nil {
		record.DBName = nullableString(filepath.Base(`MSSQLSERVER`))
	}
	*rows = append(*rows, record)
}

func valueOrZero(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}
