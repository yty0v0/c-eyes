package softwarescan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// SoftwareScanParams defines filter inputs for software scan.
type SoftwareScanParams struct {
	Groups     []int64
	Hostname   *string
	IP         *string
	Name       *string
	Version    []string
	BinPath    *string
	ConfigPath *string
	Progress   ProgressFunc
}

// SoftwareProcess is the process object associated with a software row.
type SoftwareProcess struct {
	PID   *int    `json:"pid"`
	Name  *string `json:"name"`
	Uname *string `json:"uname"`
}

// SoftwareInfo is the normalized output row for software collection.
type SoftwareInfo struct {
	ExternalIPList []string          `json:"externalIpList"`
	InternalIPList []string          `json:"internalIpList"`
	BizGroupID     *int64            `json:"bizGroupId"`
	BizGroup       *string           `json:"bizGroup"`
	Remark         *string           `json:"remark"`
	HostTagList    []string          `json:"hostTagList"`
	Hostname       *string           `json:"hostname"`
	Name           *string           `json:"name"`
	Version        *string           `json:"version"`
	Uname          *string           `json:"uname"`
	BinPath        *string           `json:"binPath"`
	ConfigPath     *string           `json:"configPath"`
	Processes      []SoftwareProcess `json:"processes"`
}

// SoftwareScanResult is the top-level output.
type SoftwareScanResult struct {
	Total int            `json:"total"`
	Rows  []SoftwareInfo `json:"rows"`
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
