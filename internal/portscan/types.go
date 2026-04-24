package portscan

// ScanMode identifies the probe strategy used by port scan.
type ScanMode string

const (
	ScanModeTCPConnect ScanMode = "tcp-connect"
	ScanModeTCPSYN     ScanMode = "tcp-syn"
)

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// PortScanParams defines filter inputs for port scan.
type PortScanParams struct {
	Groups      []int64
	Hostname    *string
	IP          *string
	Protos      []string
	Port        *int
	BindIP      *string
	ProcessName *string
	Mode        ScanMode
	Progress    ProgressFunc
}

// PortInfo is the normalized output record.
type PortInfo struct {
	DisplayIP      *string  `json:"displayIp"`
	ExternalIPList []string `json:"externalIpList"`
	InternalIPList []string `json:"internalIpList"`
	ExternalIP     *string  `json:"externalIp"`
	InternalIP     *string  `json:"internalIp"`
	BizGroupID     *int64   `json:"bizGroupId"`
	BizGroup       *string  `json:"bizGroup"`
	Remark         *string  `json:"remark"`
	HostTagList    []string `json:"hostTagList"`
	Proto          *string  `json:"proto"`
	Port           *int     `json:"port"`
	PID            *int     `json:"pid"`
	ProcessName    *string  `json:"processName"`
	BindIP         *string  `json:"bindIp"`
	Status         *int     `json:"status"`
}

// PortScanResult is the top-level output.
type PortScanResult struct {
	Total int        `json:"total"`
	Rows  []PortInfo `json:"rows"`
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
