package benchmark

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func resolveTemplate(selected Template) (Template, error) {
	if selected == "" {
		selected = TemplateAuto
	}

	detected, err := detectTemplateFromRuntime(runtime.GOOS)
	if err != nil {
		return "", err
	}
	if selected == TemplateAuto {
		return detected, nil
	}
	if selected != detected {
		return "", fmt.Errorf("invalid argument: template %s does not match current system (%s), expected %s", selected, runtime.GOOS, detected)
	}
	return selected, nil
}

func detectTemplateFromRuntime(goos string) (Template, error) {
	if normalizeLowerTrim(goos) == "windows" {
		return TemplateWindows, nil
	}
	if normalizeLowerTrim(goos) != "linux" {
		return TemplateLinux, nil
	}

	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		// Keep a conservative fallback when distro metadata is unavailable.
		return TemplateLinux, nil
	}
	return detectLinuxTemplateFromOSRelease(string(content)), nil
}

func detectLinuxTemplateFromOSRelease(content string) Template {
	id := ""
	idLike := ""

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := normalizeLowerTrim(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch key {
		case "id":
			id = normalizeLowerTrim(val)
		case "id_like":
			idLike = normalizeLowerTrim(val)
		}
	}

	corpus := strings.TrimSpace(id + " " + idLike)
	if corpus == "" {
		return TemplateLinux
	}
	if containsAnyToken(corpus, []string{"euler", "euleros", "openeuler"}) {
		return TemplateEulerOS
	}
	if containsAnyToken(corpus, []string{"kylin", "neokylin", "galaxykylin", "kysec"}) {
		return TemplateKylin
	}
	return TemplateLinux
}

func containsAnyToken(corpus string, keys []string) bool {
	normalized := " " + strings.ReplaceAll(normalizeLowerTrim(corpus), "\t", " ") + " "
	for _, key := range keys {
		token := " " + normalizeLowerTrim(key) + " "
		if strings.Contains(normalized, token) || strings.Contains(normalized, normalizeLowerTrim(key)) {
			return true
		}
	}
	return false
}

func templateFolder(template Template) (string, error) {
	switch template {
	case TemplateWindows:
		return "windows", nil
	case TemplateLinux:
		return "linux", nil
	case TemplateEulerOS:
		return "euleros", nil
	case TemplateKylin:
		return "kylin", nil
	default:
		return "", fmt.Errorf("invalid argument: unsupported benchmark template: %s", template)
	}
}
