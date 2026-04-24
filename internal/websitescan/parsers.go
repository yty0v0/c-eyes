package websitescan

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var (
	reNginxRoot       = regexp.MustCompile(`(?mi)^\s*root\s+([^;#\r\n]+)\s*;`)
	reNginxServerName = regexp.MustCompile(`(?mi)^\s*server_name\s+([^;#\r\n]+)\s*;`)
	reNginxAllow      = regexp.MustCompile(`(?mi)^\s*allow\s+([^;#\r\n]+)\s*;`)
	reNginxDeny       = regexp.MustCompile(`(?mi)^\s*deny\s+([^;#\r\n]+)\s*;`)
	reNginxListen     = regexp.MustCompile(`(?mi)^\s*listen\s+([^;#\r\n]+)\s*;`)
	reNginxModSec     = regexp.MustCompile(`(?mi)^\s*modsecurity\s+on\s*;`)

	reApacheRoot   = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+("?[^"\r\n#]+"?)`)
	reApacheServer = regexp.MustCompile(`(?mi)^\s*ServerName\s+("?[^"\r\n#]+"?)`)
	reApacheListen = regexp.MustCompile(`(?mi)^\s*Listen\s+([^\s#]+)`)

	reTomcatAppBase   = regexp.MustCompile(`(?i)\bappBase\s*=\s*"([^"]+)"`)
	reTomcatHostName  = regexp.MustCompile(`(?i)\bname\s*=\s*"([^"]+)"`)
	reTomcatConnector = regexp.MustCompile(`(?i)<Connector[^>]*\bport\s*=\s*"([^"]+)"[^>]*>`)
	reTomcatProtocol  = regexp.MustCompile(`(?i)\bprotocol\s*=\s*"([^"]+)"`)
)

func parseNginx(content string) (webRoot string, domains []DomainInfo, port *int, proto, allow, deny string, securityEnabled bool) {
	if m := reNginxRoot.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanToken(m[1])
	}
	if m := reNginxServerName.FindStringSubmatch(content); len(m) > 1 {
		for _, item := range strings.Fields(cleanToken(m[1])) {
			domains = append(domains, DomainInfo{Name: nullableString(item), Title: nil, IP: nil})
		}
	}
	if m := reNginxListen.FindStringSubmatch(content); len(m) > 1 {
		p, pr := parseListenValue(m[1])
		port = p
		proto = pr
	}
	if m := reNginxAllow.FindStringSubmatch(content); len(m) > 1 {
		allow = cleanToken(m[1])
	}
	if m := reNginxDeny.FindStringSubmatch(content); len(m) > 1 {
		deny = cleanToken(m[1])
	}
	securityEnabled = reNginxModSec.MatchString(content)
	return webRoot, domains, port, proto, allow, deny, securityEnabled
}

func parseApache(content string) (webRoot string, domains []DomainInfo, port *int, proto string) {
	if m := reApacheRoot.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanToken(m[1])
	}
	if m := reApacheServer.FindStringSubmatch(content); len(m) > 1 {
		domain := cleanToken(m[1])
		if domain != "" {
			domains = append(domains, DomainInfo{Name: strPtr(domain), Title: nil, IP: nil})
		}
	}
	if m := reApacheListen.FindStringSubmatch(content); len(m) > 1 {
		port = parsePortFromListenToken(m[1])
	}
	if port != nil {
		proto = toProtoFromPort(*port)
	}
	return webRoot, domains, port, proto
}

func parseTomcat(content string) (webRoot string, domains []DomainInfo, port *int, proto string) {
	if m := reTomcatAppBase.FindStringSubmatch(content); len(m) > 1 {
		webRoot = cleanToken(m[1])
	}
	if m := reTomcatHostName.FindStringSubmatch(content); len(m) > 1 {
		domain := cleanToken(m[1])
		if domain != "" {
			domains = append(domains, DomainInfo{Name: strPtr(domain), Title: nil, IP: nil})
		}
	}
	port, proto = parseTomcatConnector(content)
	return webRoot, domains, port, proto
}

func parseTomcatConnector(content string) (*int, string) {
	decoder := xml.NewDecoder(strings.NewReader(content))
	var nonAJPPort *int
	var nonAJPProto string
	var fallbackPort *int
	var fallbackProto string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "Connector") {
			continue
		}

		attrs := make(map[string]string, len(start.Attr))
		for _, attr := range start.Attr {
			attrs[strings.ToLower(strings.TrimSpace(attr.Name.Local))] = strings.TrimSpace(attr.Value)
		}

		port := parsePort(attrs["port"])
		if port == nil {
			continue
		}

		proto := inferTomcatProto(attrs, *port)
		if !strings.Contains(strings.ToLower(attrs["protocol"]), "ajp") {
			// Prefer TLS-enabled HTTP connectors when both HTTP and HTTPS exist.
			if proto == "https" {
				return port, proto
			}
			if nonAJPPort == nil {
				nonAJPPort = port
				nonAJPProto = proto
			}
			continue
		}
		if fallbackPort == nil {
			fallbackPort = port
			fallbackProto = proto
		}
	}

	if nonAJPPort != nil {
		return nonAJPPort, nonAJPProto
	}

	if fallbackPort != nil {
		return fallbackPort, fallbackProto
	}

	// Regex fallback for malformed but still parseable snippets.
	if m := reTomcatConnector.FindStringSubmatch(content); len(m) > 1 {
		port := parsePort(cleanToken(m[1]))
		if port == nil {
			return nil, ""
		}
		proto := ""
		if pm := reTomcatProtocol.FindStringSubmatch(m[0]); len(pm) > 1 {
			p := strings.ToLower(cleanToken(pm[1]))
			if strings.Contains(p, "https") {
				proto = "https"
			}
		}
		if proto == "" {
			proto = toProtoFromPort(*port)
		}
		return port, proto
	}

	return nil, ""
}

func inferTomcatProto(attrs map[string]string, port int) string {
	if strings.EqualFold(attrs["scheme"], "https") {
		return "https"
	}
	if parseTomcatBool(attrs["secure"]) || parseTomcatBool(attrs["sslenabled"]) {
		return "https"
	}
	if strings.Contains(strings.ToLower(attrs["protocol"]), "https") {
		return "https"
	}
	return toProtoFromPort(port)
}

func parseTomcatBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseListenValue(raw string) (*int, string) {
	token := strings.Fields(cleanToken(raw))
	if len(token) == 0 {
		return nil, ""
	}
	port := parsePortFromListenToken(token[0])
	if port == nil {
		return nil, ""
	}
	proto := toProtoFromPort(*port)
	line := strings.ToLower(cleanToken(raw))
	if strings.Contains(line, "ssl") {
		proto = "https"
	}
	return port, proto
}

func parsePortFromListenToken(token string) *int {
	value := cleanToken(token)
	value = strings.TrimPrefix(value, "[::]:")
	if strings.Count(value, ":") > 0 {
		parts := strings.Split(value, ":")
		value = parts[len(parts)-1]
	}
	if value == "*" {
		return nil
	}
	return parsePort(value)
}

func cleanToken(v string) string {
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

type iisApplicationHost struct {
	Sites struct {
		Site []struct {
			Name         string `xml:"name,attr"`
			ServerAutoOn string `xml:"serverAutoStart,attr"`
			Bindings     []struct {
				Protocol           string `xml:"protocol,attr"`
				BindingInformation string `xml:"bindingInformation,attr"`
			} `xml:"bindings>binding"`
			Applications []struct {
				Path             string `xml:"path,attr"`
				ApplicationPool  string `xml:"applicationPool,attr"`
				VirtualDirectory []struct {
					Path         string `xml:"path,attr"`
					PhysicalPath string `xml:"physicalPath,attr"`
				} `xml:"virtualDirectory"`
			} `xml:"application"`
		} `xml:"site"`
	} `xml:"system.applicationHost>sites"`
	ApplicationPools struct {
		Add []struct {
			Name         string `xml:"name,attr"`
			ProcessModel struct {
				IdentityType string `xml:"identityType,attr"`
				UserName     string `xml:"userName,attr"`
			} `xml:"processModel"`
		} `xml:"add"`
	} `xml:"system.applicationHost>applicationPools"`
}

func parseIISApplicationHost(content []byte) []WebSiteInfo {
	decoder := xml.NewDecoder(bytes.NewReader(content))
	var cfg iisApplicationHost
	if err := decoder.Decode(&cfg); err != nil {
		return nil
	}

	poolIndex := map[string]AppPoolInfo{}
	for _, p := range cfg.ApplicationPools.Add {
		pool := AppPoolInfo{Name: nullableString(p.Name), User: nullableString(p.ProcessModel.UserName)}
		if id := parseIdentityType(p.ProcessModel.IdentityType); id != nil {
			pool.IdentityType = id
		}
		poolIndex[strings.ToLower(strings.TrimSpace(p.Name))] = pool
	}

	out := make([]WebSiteInfo, 0, len(cfg.Sites.Site))
	for _, site := range cfg.Sites.Site {
		row := WebSiteInfo{
			Type:         strPtr("iis"),
			ConfigName:   nullableString(site.Name),
			Domains:      []DomainInfo{},
			VirtualDir:   []VirtualDirInfo{},
			PortStatus:   intPtr(-1),
			BindingCount: intPtr(0),
		}
		if strings.TrimSpace(site.ServerAutoOn) != "" {
			if strings.EqualFold(strings.TrimSpace(site.ServerAutoOn), "true") {
				row.State = intPtr(1)
			} else {
				row.State = intPtr(0)
			}
		}

		for _, b := range site.Bindings {
			ip, port, host := parseBindingInformation(b.BindingInformation)
			if row.Port == nil && port != nil {
				row.Port = port
			}
			if row.Proto == nil {
				if p := strings.ToLower(strings.TrimSpace(b.Protocol)); p != "" {
					row.Proto = strPtr(p)
				}
			}
			if host != "" {
				row.Domains = append(row.Domains, DomainInfo{Name: strPtr(host), Title: nil, IP: nullableString(ip)})
			}
		}
		if row.BindingCount == nil {
			row.BindingCount = intPtr(len(row.Domains))
		} else {
			*row.BindingCount = len(row.Domains)
		}

		for _, app := range site.Applications {
			var pool *AppPoolInfo
			if candidate, ok := poolIndex[strings.ToLower(strings.TrimSpace(app.ApplicationPool))]; ok {
				copy := candidate
				pool = &copy
				if row.User == nil {
					row.User = copy.User
				}
			}
			for _, vd := range app.VirtualDirectory {
				isRoot := strings.TrimSpace(vd.Path) == "/"
				item := VirtualDirInfo{
					Path:         nullableString(vd.Path),
					PhysicalPath: nullableString(vd.PhysicalPath),
					Root:         boolPtr(isRoot),
					ACLs:         []ACLInfo{},
					AppPath:      nullableString(app.Path),
					AppPool:      pool,
				}
				row.VirtualDir = append(row.VirtualDir, item)
				if isRoot && row.Root == nil {
					rootCopy := item
					row.Root = &rootCopy
					row.Path = rootCopy.PhysicalPath
				}
			}
		}
		row.VirtualDirCount = intPtr(len(row.VirtualDir))
		out = append(out, row)
	}
	return out
}

func parseBindingInformation(v string) (ip string, port *int, host string) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) >= 1 {
		ip = strings.TrimSpace(parts[0])
	}
	if len(parts) >= 2 {
		port = parsePort(parts[1])
	}
	if len(parts) >= 3 {
		host = strings.TrimSpace(parts[2])
	}
	return ip, port, host
}

func parseIdentityType(v string) *int {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" {
		return nil
	}
	if n, err := strconv.Atoi(trimmed); err == nil {
		return intPtr(n)
	}
	switch strings.ToLower(trimmed) {
	case "localsystem":
		return intPtr(0)
	case "localservice":
		return intPtr(1)
	case "networkservice":
		return intPtr(2)
	case "specificuser":
		return intPtr(3)
	default:
		return nil
	}
}
