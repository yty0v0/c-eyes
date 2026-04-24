package webapplicationscan

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reNginxRoot       = regexp.MustCompile(`(?mi)^\s*root\s+([^;#\r\n]+)\s*;`)
	reNginxServerName = regexp.MustCompile(`(?mi)^\s*server_name\s+([^;#\r\n]+)\s*;`)
	reNginxModule     = regexp.MustCompile(`(?mi)^\s*load_module\s+([^;#\r\n]+)\s*;`)
	reApacheRoot      = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+("?[^"\r\n#]+"?)`)
	reApacheServer    = regexp.MustCompile(`(?mi)^\s*ServerName\s+("?[^"\r\n#]+"?)`)
	reApacheModule    = regexp.MustCompile(`(?mi)^\s*LoadModule\s+([^\s#]+)\s+([^\s#]+)`)
	reTomcatAppBase   = regexp.MustCompile(`(?i)\bappBase\s*=\s*"([^"]+)"`)
	reTomcatName      = regexp.MustCompile(`(?i)\bname\s*=\s*"([^"]+)"`)
	reVersion         = regexp.MustCompile(`([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)
)

func parseNginxConfig(content string) (webRoot, domain string, plugins []PluginInfo) {
	if m := reNginxRoot.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanConfigToken(m[1])
	}
	if m := reNginxServerName.FindStringSubmatch(content); len(m) > 1 {
		items := strings.Fields(cleanConfigToken(m[1]))
		if len(items) > 0 {
			domain = items[0]
		}
	}
	for _, m := range reNginxModule.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		modulePath := cleanConfigToken(m[1])
		base := filepath.Base(modulePath)
		plugins = append(plugins, PluginInfo{
			PluginName:  nullableString(base),
			PluginURI:   nil,
			Description: strPtr("nginx dynamic module"),
			Author:      nil,
			AuthorURI:   nil,
			Version:     nil,
		})
	}
	return webRoot, domain, plugins
}

func parseApacheConfig(content string) (webRoot, domain string, plugins []PluginInfo) {
	if m := reApacheRoot.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanConfigToken(m[1])
	}
	if m := reApacheServer.FindStringSubmatch(content); len(m) > 1 {
		domain = cleanConfigToken(m[1])
	}
	for _, m := range reApacheModule.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		moduleName := cleanConfigToken(m[1])
		modulePath := cleanConfigToken(m[2])
		plugins = append(plugins, PluginInfo{
			PluginName:  nullableString(moduleName),
			PluginURI:   nil,
			Description: nullableString(modulePath),
			Author:      nil,
			AuthorURI:   nil,
			Version:     nil,
		})
	}
	return webRoot, domain, plugins
}

func parseTomcatConfig(content string) (webRoot, domain string) {
	if m := reTomcatAppBase.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanConfigToken(m[1])
	}
	if m := reTomcatName.FindStringSubmatch(content); len(m) > 1 {
		domain = cleanConfigToken(m[1])
	}
	return webRoot, domain
}

func detectVersionFromText(values ...string) *string {
	for _, v := range values {
		m := reVersion.FindStringSubmatch(v)
		if len(m) > 1 {
			return nullableString(m[1])
		}
	}
	return nil
}

func cleanConfigToken(v string) string {
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

type iisConfiguration struct {
	Sites struct {
		Site []struct {
			Name        string `xml:"name,attr"`
			Application []struct {
				VirtualDirectory []struct {
					PhysicalPath string `xml:"physicalPath,attr"`
				} `xml:"virtualDirectory"`
			} `xml:"application"`
		} `xml:"site"`
	} `xml:"system.applicationHost>sites"`
}

func parseIISApplicationHost(content []byte) []WebApplicationInfo {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	var cfg iisConfiguration
	if err := decoder.Decode(&cfg); err != nil {
		return nil
	}
	out := make([]WebApplicationInfo, 0, len(cfg.Sites.Site))
	for _, site := range cfg.Sites.Site {
		var root string
		for _, app := range site.Application {
			for _, vd := range app.VirtualDirectory {
				if strings.TrimSpace(vd.PhysicalPath) != "" {
					root = strings.TrimSpace(vd.PhysicalPath)
					break
				}
			}
			if root != "" {
				break
			}
		}
		row := WebApplicationInfo{
			AppName:     strPtr("iis"),
			ServerName:  strPtr("iis"),
			RootPath:    nullableString(root),
			WebRoot:     nullableString(root),
			DomainName:  nullableString(site.Name),
			Description: strPtr("IIS site"),
			Plugins:     []PluginInfo{},
			PluginCount: intPtr(0),
		}
		out = append(out, row)
	}
	return out
}
