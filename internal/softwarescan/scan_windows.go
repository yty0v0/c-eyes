//go:build windows

package softwarescan

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsServiceInfo struct {
	Name      string
	ImagePath string
}

var windowsVersionRe = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})`)
var windowsListServicesFn = listWindowsServices

func collectSoftware(ctx context.Context) ([]SoftwareInfo, error) {
	rows, err := collectSoftwareFromProcesses(ctx)
	if err != nil {
		return nil, err
	}

	for _, svc := range windowsListServicesFn() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		args := parseWindowsCommandLine(svc.ImagePath)
		exe := ""
		if len(args) > 0 {
			exe = strings.TrimSpace(args[0])
		}
		name := normalizeWindowsServiceName(svc.Name, exe)
		row := SoftwareInfo{
			Name:       nullableString(name),
			Version:    nullableString(detectVersionFromText(svc.ImagePath)),
			BinPath:    normalizePath(exe),
			ConfigPath: extractConfigPath(svc.ImagePath, normalizePath(exe)),
			Processes:  []SoftwareProcess{},
		}
		if row.BinPath == nil && row.ConfigPath == nil {
			continue
		}
		rows = append(rows, row)
	}

	rows = append(rows, collectWindowsUninstallSoftware()...)
	rows = append(rows, collectWindowsStaticConfigSoftware()...)
	return rows, nil
}

func collectWindowsUninstallSoftware() []SoftwareInfo {
	roots := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	rows := make([]SoftwareInfo, 0, 32)
	for _, rootPath := range roots {
		root, err := registry.OpenKey(registry.LOCAL_MACHINE, rootPath, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := root.ReadSubKeyNames(-1)
		if err != nil {
			_ = root.Close()
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(root, name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			displayName, _, _ := sub.GetStringValue("DisplayName")
			displayVersion, _, _ := sub.GetStringValue("DisplayVersion")
			installLocation, _, _ := sub.GetStringValue("InstallLocation")
			displayIcon, _, _ := sub.GetStringValue("DisplayIcon")
			_ = sub.Close()

			softwareName := strings.TrimSpace(displayName)
			if softwareName == "" {
				continue
			}

			binPath := normalizePath(installLocation)
			if binPath == nil {
				icon := strings.TrimSpace(displayIcon)
				if idx := strings.Index(icon, ","); idx >= 0 {
					icon = strings.TrimSpace(icon[:idx])
				}
				binPath = normalizePath(icon)
			}
			if binPath == nil {
				continue
			}

			rows = append(rows, SoftwareInfo{
				Name:      nullableString(softwareName),
				Version:   nullableString(displayVersion),
				BinPath:   binPath,
				Processes: []SoftwareProcess{},
			})
		}
		_ = root.Close()
	}
	return rows
}

func collectWindowsStaticConfigSoftware() []SoftwareInfo {
	rows := make([]SoftwareInfo, 0, 4)
	systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if systemRoot != "" {
		iisConfig := filepath.Join(systemRoot, "System32", "inetsrv", "config", "applicationHost.config")
		if _, err := os.Stat(iisConfig); err == nil {
			rows = append(rows, SoftwareInfo{
				Name:       strPtr("iis"),
				ConfigPath: normalizePath(iisConfig),
				Processes:  []SoftwareProcess{},
			})
		}
	}

	for _, item := range []struct {
		name string
		path string
	}{
		{name: "nginx", path: `C:\nginx\conf\nginx.conf`},
		{name: "apache", path: `C:\Apache24\conf\httpd.conf`},
		{name: "tomcat", path: `C:\Tomcat\conf\server.xml`},
	} {
		if _, err := os.Stat(item.path); err == nil {
			rows = append(rows, SoftwareInfo{
				Name:       strPtr(item.name),
				ConfigPath: normalizePath(item.path),
				Processes:  []SoftwareProcess{},
			})
		}
	}
	return rows
}

func listWindowsServices() []windowsServiceInfo {
	services, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer services.Close()

	names, _ := services.ReadSubKeyNames(-1)
	out := make([]windowsServiceInfo, 0, len(names))
	for _, name := range names {
		svc, err := registry.OpenKey(services, name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		imagePath, _, _ := svc.GetStringValue("ImagePath")
		_ = svc.Close()
		out = append(out, windowsServiceInfo{Name: name, ImagePath: imagePath})
	}
	return out
}

func parseWindowsCommandLine(command string) []string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil
	}
	args, err := windows.DecomposeCommandLine(trimmed)
	if err == nil && len(args) > 0 {
		return args
	}
	return splitCommandLineLoose(trimmed)
}

func normalizeWindowsServiceName(serviceName, executable string) string {
	target := strings.ToLower(strings.TrimSpace(serviceName + " " + executable))
	base := strings.ToLower(filepath.Base(strings.TrimSpace(executable)))
	switch {
	case strings.Contains(target, "nginx"), base == "nginx.exe":
		return "nginx"
	case strings.Contains(target, "apache"), base == "httpd.exe":
		return "apache"
	case strings.Contains(target, "tomcat"), base == "tomcat9.exe", base == "tomcat10.exe":
		return "tomcat"
	case strings.Contains(target, "w3svc"), strings.Contains(target, "iis"), base == "w3wp.exe":
		return "iis"
	case strings.Contains(target, "mysql"), base == "mysqld.exe":
		return "mysql"
	case strings.Contains(target, "postgres"), base == "postgres.exe":
		return "postgresql"
	case strings.Contains(target, "redis"), base == "redis-server.exe":
		return "redis"
	default:
	}

	if normalized := normalizeNameFromPathOrLabel(serviceName); normalized != "" {
		return normalized
	}
	return normalizeNameFromPathOrLabel(base)
}

func detectVersionFromText(raw string) string {
	matches := windowsVersionRe.FindStringSubmatch(raw)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
