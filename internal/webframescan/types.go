package webframescan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// WebFrameScanParams defines filter inputs for web framework scan.
type WebFrameScanParams struct {
	Groups     []int64
	Hostname   *string
	IP         *string
	Name       *string
	Version    *string
	Type       []string
	ServerName []string
	Progress   ProgressFunc
}

// JarRecord is normalized jar metadata.
type JarRecord struct {
	Version *string `json:"version"`
	AbsDir  *string `json:"absDir"`
	JarName *string `json:"jarName"`
}

// WebFrameRecord is the normalized output row for web framework collection.
type WebFrameRecord struct {
	DisplayIP      *string     `json:"displayIp"`
	ExternalIPList []string    `json:"externalIpList"`
	InternalIPList []string    `json:"internalIpList"`
	BizGroupID     *int64      `json:"bizGroupId"`
	BizGroup       *string     `json:"bizGroup"`
	Remark         *string     `json:"remark"`
	HostTagList    []string    `json:"hostTagList"`
	Hostname       *string     `json:"hostname"`
	Name           *string     `json:"name"`
	Version        *string     `json:"version"`
	Type           *string     `json:"type"`
	ServerName     *string     `json:"serverName"`
	DomainName     *string     `json:"domainName"`
	WebAppDir      *string     `json:"webAppDir"`
	JarCount       *string     `json:"jarCount"`
	JarList        []JarRecord `json:"jarList"`
	WebRoot        *string     `json:"webRoot"`
	WorkDir        *string     `json:"workDir"`
}

// WebFrameScanResult is the top-level output.
type WebFrameScanResult struct {
	Total int              `json:"total"`
	Rows  []WebFrameRecord `json:"rows"`
}

func strPtr(v string) *string {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}
