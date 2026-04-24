package environmentscan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// EnvironmentScanParams defines filter inputs for environment variable scan.
type EnvironmentScanParams struct {
	Groups   []int64
	Hostname *string
	IP       *string
	Key      *string
	Value    *string
	User     *string
	SysEnv   []bool
	Progress ProgressFunc
}

// EnvironmentInfo is the normalized environment-variable output record.
type EnvironmentInfo struct {
	DisplayIP      *string  `json:"displayIp"`
	ExternalIPList []string `json:"externalIpList"`
	InternalIPList []string `json:"internalIpList"`
	BizGroupID     *int64   `json:"bizGroupId"`
	BizGroup       *string  `json:"bizGroup"`
	Remark         *string  `json:"remark"`
	HostTagList    []string `json:"hostTagList"`
	Hostname       *string  `json:"hostname"`
	Key            *string  `json:"key"`
	Value          *string  `json:"value"`
	User           *string  `json:"user"`
	SysEnv         *bool    `json:"sysEnv"`
}

// EnvironmentScanResult is the top-level output.
type EnvironmentScanResult struct {
	Total int               `json:"total"`
	Rows  []EnvironmentInfo `json:"rows"`
}

func strPtr(v string) *string {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}
