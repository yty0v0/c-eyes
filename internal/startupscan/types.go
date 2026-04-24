package startupscan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// StartupScanParams defines filter inputs for startup scan.
type StartupScanParams struct {
	Groups      []int64
	Hostname    *string
	IP          *string
	Name        *string
	InitLevel   []int
	DefaultOpen []bool
	IsXinetd    []bool
	ShowName    *string
	User        *string
	Enable      *bool
	StartType   []int
	Publisher   *string
	Progress    ProgressFunc
}

// StartupInfo is the normalized output record.
type StartupInfo struct {
	DisplayIP      *string  `json:"displayIp"`
	ExternalIPList []string `json:"externalIpList"`
	InternalIPList []string `json:"internalIpList"`
	ExternalIP     *string  `json:"externalIp"`
	InternalIP     *string  `json:"internalIp"`
	BizGroupID     *int64   `json:"bizGroupId"`
	BizGroup       *string  `json:"bizGroup"`
	Remark         *string  `json:"remark"`
	HostTagList    []string `json:"hostTagList"`
	Hostname       *string  `json:"hostname"`
	Name           *string  `json:"name"`
	DefaultOpen    *bool    `json:"defaultOpen"`
	RC0            *int     `json:"rc0"`
	RC1            *int     `json:"rc1"`
	RC2            *int     `json:"rc2"`
	RC3            *int     `json:"rc3"`
	RC4            *int     `json:"rc4"`
	RC5            *int     `json:"rc5"`
	RC6            *int     `json:"rc6"`
	RC7            *int     `json:"rc7"`
	InitLevel      *int     `json:"initLevel"`
	Xinetd         *bool    `json:"xinetd"`
	User           *string  `json:"user"`
	Enable         *bool    `json:"enable"`
	StartType      *int     `json:"startType"`
	Publisher      *string  `json:"publisher"`
	ShowName       *string  `json:"showName"`
	ExecPath       *string  `json:"execPath"`
}

// StartupScanResult is the top-level output.
type StartupScanResult struct {
	Total int           `json:"total"`
	Rows  []StartupInfo `json:"rows"`
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
