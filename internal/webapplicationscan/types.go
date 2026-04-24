package webapplicationscan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// WebApplicationScanParams defines filter inputs for web application scan.
type WebApplicationScanParams struct {
	Groups     []int64
	Hostname   *string
	IP         *string
	Version    []string
	AppName    *string
	RootPath   *string
	WebRoot    *string
	ServerName []string
	DomainName *string
	Progress   ProgressFunc
}

// PluginInfo is normalized plugin metadata.
type PluginInfo struct {
	PluginName  *string `json:"pluginName"`
	PluginURI   *string `json:"pluginUri"`
	Description *string `json:"description"`
	Author      *string `json:"author"`
	AuthorURI   *string `json:"authorUri"`
	Version     *string `json:"version"`
}

// WebApplicationInfo is the normalized output row for web application collection.
type WebApplicationInfo struct {
	DisplayIP      *string      `json:"displayIp"`
	ExternalIPList []string     `json:"externalIpList"`
	InternalIPList []string     `json:"internalIpList"`
	BizGroupID     *int64       `json:"bizGroupId"`
	BizGroup       *string      `json:"bizGroup"`
	Remark         *string      `json:"remark"`
	HostTagList    []string     `json:"hostTagList"`
	Hostname       *string      `json:"hostname"`
	Version        *string      `json:"version"`
	WebRoot        *string      `json:"webRoot"`
	ServerName     *string      `json:"serverName"`
	DomainName     *string      `json:"domainName"`
	PluginCount    *int         `json:"pluginCount"`
	AppName        *string      `json:"appName"`
	Description    *string      `json:"description"`
	RootPath       *string      `json:"rootPath"`
	Plugins        []PluginInfo `json:"plugins"`
	IsRunning      *bool        `json:"isRunning"`
}

// WebApplicationScanResult is the top-level output.
type WebApplicationScanResult struct {
	Total int                  `json:"total"`
	Rows  []WebApplicationInfo `json:"rows"`
}

func strPtr(v string) *string {
	return &v
}

func intPtr(v int) *int {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}
