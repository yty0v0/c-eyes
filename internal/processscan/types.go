package processscan

import "time"

// ProcessScanParams defines filter inputs for a process scan.
// 定义输入参数结构
type ProcessScanParams struct {
	Hostname        *string
	IP              *string
	StartTime       *time.Time
	Versions        []string
	Root            *bool
	PackageName     *string
	PackageVersions []string
	InstalledByPm   *bool
	PIDs            []int
	State           *string
	Path            *string
	Uname           *string
	Gname           *string
	Name            *string
	StartArgs       *string
	TTY             *string
	Description     *string
	Types           []int
	Progress        ProgressFunc
}

// ProgressFunc reports process-scan progress.
type ProgressFunc func(done, total int, stage string)

// ProcessInfo is the normalized output for a single process.
// 定义输出参数结构
type ProcessInfo struct {
	DisplayIP             *string    `json:"displayIp"`
	ExternalIPList        []string   `json:"externalIpList"`
	InternalIPList        []string   `json:"internalIpList"`
	ProcessExternalIPList []string   `json:"processExternalIpList"`
	BizGroupID            *int64     `json:"bizGroupId"`
	BizGroup              *string    `json:"bizGroup"`
	Remark                *string    `json:"remark"`
	HostTagList           []string   `json:"hostTagList"`
	Hostname              *string    `json:"hostname"`
	StartTime             *time.Time `json:"startTime"`
	Version               *string    `json:"version"`
	Root                  *bool      `json:"root"`
	PrtCount              *int       `json:"prtCount"`
	Md5                   *string    `json:"Md5"`
	PackageName           *string    `json:"packageName"`
	PackageVersion        *string    `json:"packageVersion"`
	InstallByPm           *bool      `json:"installByPm"`
	PID                   *int       `json:"pid"`
	PPID                  *int       `json:"ppid"`
	Path                  *string    `json:"path"`
	StartArgs             *string    `json:"startArgs"`
	State                 *string    `json:"state"`
	Uname                 *string    `json:"uname"`
	UID                   *int64     `json:"uid"`
	Gname                 *string    `json:"gname"`
	GID                   *int64     `json:"gid"`
	TTY                   *string    `json:"tty"`
	Name                  *string    `json:"name"`
	SessionID             *int       `json:"sessionId"`
	SessionName           *string    `json:"sessionName"`
	Type                  *int       `json:"type"`
	Description           *string    `json:"description"`
	Groups                []string   `json:"groups"`
	Size                  *int64     `json:"size"`
}

// HostInfo contains host-level metadata applied to each process.
// 定义辅助结构与指针工具
type HostInfo struct {
	Hostname    string
	IPs         []string
	InternalIPs []string
	ExternalIPs []string
	DisplayIP   *string
	BizGroupID  *int64
	BizGroup    *string
	Remark      *string
	HostTagList []string
}

type Config struct {
	DisplayIP      *string  `json:"displayIp"`
	ExternalIPList []string `json:"externalIpList"`
	InternalIPList []string `json:"internalIpList"`
	BizGroupID     *int64   `json:"bizGroupId"`
	BizGroup       *string  `json:"bizGroup"`
	Remark         *string  `json:"remark"`
	HostTagList    []string `json:"hostTagList"`
}

func strPtr(val string) *string {
	return &val
}

func intPtr(val int) *int {
	return &val
}

func int64Ptr(val int64) *int64 {
	return &val
}

func boolPtr(val bool) *bool {
	return &val
}

func timePtr(val time.Time) *time.Time {
	return &val
}
