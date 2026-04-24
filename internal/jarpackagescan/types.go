package jarpackagescan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// JarPackageScanParams defines filter inputs for jar package scan.
type JarPackageScanParams struct {
	Groups     []int64
	Hostname   *string
	IP         *string
	Name       *string
	Version    []string
	Type       []int
	Executable []bool
	Path       *string
	Progress   ProgressFunc
}

// JarPackageRecord is the normalized output row for jar package collection.
type JarPackageRecord struct {
	DisplayIP      *string  `json:"displayIp"`
	ExternalIPList []string `json:"externalIpList"`
	InternalIPList []string `json:"internalIpList"`
	BizGroupID     *int64   `json:"bizGroupId"`
	BizGroup       *string  `json:"bizGroup"`
	Remark         *string  `json:"remark"`
	HostTagList    []string `json:"hostTagList"`
	Hostname       *string  `json:"hostname"`
	Name           *string  `json:"name"`
	Version        *string  `json:"version"`
	Type           *int     `json:"type"`
	Executable     *bool    `json:"executable"`
	Path           *string  `json:"path"`
}

// JarPackageScanResult is the top-level output.
type JarPackageScanResult struct {
	Total int                `json:"total"`
	Rows  []JarPackageRecord `json:"rows"`
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
