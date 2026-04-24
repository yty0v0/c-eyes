package kernelscan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// KernelScanParams defines filter inputs for kernel module scan.
type KernelScanParams struct {
	Groups     []int64
	Hostname   *string
	IP         *string
	ModuleName *string
	Path       *string
	Version    []string
	Progress   ProgressFunc
}

// KernelModuleInfo is the normalized kernel module output record.
type KernelModuleInfo struct {
	DisplayIP   *string  `json:"displayIp"`
	ExternalIPs []string `json:"externalIps"`
	InternalIPs []string `json:"internalIps"`
	BizGroupID  *int64   `json:"bizGroupId"`
	BizGroup    *string  `json:"bizGroup"`
	Remark      *string  `json:"remark"`
	HostTagList []string `json:"hostTagList"`
	Hostname    *string  `json:"hostname"`
	ModuleName  *string  `json:"moduleName"`
	Description *string  `json:"description"`
	Path        *string  `json:"path"`
	Version     *string  `json:"version"`
	Size        *string  `json:"size"`
	Depends     []string `json:"depends"`
	Holders     []string `json:"holders"`
}

// KernelScanResult is the top-level output.
type KernelScanResult struct {
	Total int                `json:"total"`
	Rows  []KernelModuleInfo `json:"rows"`
}

func strPtr(v string) *string {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}
