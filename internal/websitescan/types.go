package websitescan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// WebSiteScanParams defines filter inputs for web site scan.
type WebSiteScanParams struct {
	Groups   []int64
	Hostname *string
	IP       *string
	Port     *int
	Proto    *string
	Type     []string
	RootPath *string
	Progress ProgressFunc
}

// DomainInfo is normalized domain binding info.
type DomainInfo struct {
	Name  *string `json:"name"`
	Title *string `json:"title"`
	IP    *string `json:"ip"`
}

// ACLInfo describes Windows ACL item.
type ACLInfo struct {
	AceType    *int    `json:"aceType"`
	User       *string `json:"user"`
	UserType   *int    `json:"userType"`
	AccessMask *int64  `json:"accessMask"`
}

// AppPoolInfo describes IIS app pool fields.
type AppPoolInfo struct {
	Name         *string `json:"name"`
	IdentityType *int    `json:"identityType"`
	User         *string `json:"user"`
}

// VirtualDirInfo is normalized virtual directory object.
type VirtualDirInfo struct {
	Path         *string      `json:"path"`
	PhysicalPath *string      `json:"physicalPath"`
	Root         *bool        `json:"root"`
	Owner        *string      `json:"owner"`
	Group        *int64       `json:"group"`
	Permission   *string      `json:"permission"`
	ACLs         []ACLInfo    `json:"acls"`
	AppPath      *string      `json:"appPath"`
	AppPool      *AppPoolInfo `json:"appPool"`
}

// WebSiteInfo is the normalized output row for web site collection.
type WebSiteInfo struct {
	DisplayIP       *string          `json:"displayIp"`
	ExternalIPList  []string         `json:"externalIpList"`
	InternalIPList  []string         `json:"internalIpList"`
	BizGroupID      *int64           `json:"bizGroupId"`
	BizGroup        *string          `json:"bizGroup"`
	Remark          *string          `json:"remark"`
	HostTagList     []string         `json:"hostTagList"`
	Hostname        *string          `json:"hostname"`
	PID             *int             `json:"pid"`
	Allow           *string          `json:"allow"`
	Deny            *string          `json:"deny"`
	Cmd             *string          `json:"cmd"`
	Domains         []DomainInfo     `json:"domains"`
	User            *string          `json:"user"`
	Type            *string          `json:"type"`
	Port            *int             `json:"port"`
	Proto           *string          `json:"proto"`
	PortStatus      *int             `json:"portStatus"`
	SecurityEnabled *bool            `json:"securityEnabled"`
	VirtualDir      []VirtualDirInfo `json:"virtualDir"`
	Root            *VirtualDirInfo  `json:"root"`
	VirtualDirCount *int             `json:"virtualDirCount"`
	BindingCount    *int             `json:"bindingCount"`
	DeployPath      *string          `json:"deployPath"`
	ConfigName      *string          `json:"configName"`
	State           *int             `json:"state"`
	Path            *string          `json:"path"`
	IsRunning       *bool            `json:"isRunning"`
}

// WebSiteScanResult is the top-level output.
type WebSiteScanResult struct {
	Total int           `json:"total"`
	Rows  []WebSiteInfo `json:"rows"`
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
