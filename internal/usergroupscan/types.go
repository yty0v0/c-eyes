package usergroupscan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// UserGroupScanParams defines filter inputs for user-group scan.
type UserGroupScanParams struct {
	Groups   []int64
	Hostname *string
	IP       *string
	Name     *string
	GID      *int64
	Progress ProgressFunc
}

// GroupMember describes one user-group member.
type GroupMember struct {
	Name *string `json:"name"`
	Type *int    `json:"type"`
}

// UserGroupInfo is the normalized output record.
type UserGroupInfo struct {
	DisplayIP      *string       `json:"displayIp"`
	ExternalIPList []string      `json:"externalIpList"`
	InternalIPList []string      `json:"internalIpList"`
	BizGroupID     *int64        `json:"bizGroupId"`
	BizGroup       *string       `json:"bizGroup"`
	Remark         *string       `json:"remark"`
	HostTagList    []string      `json:"hostTagList"`
	Hostname       *string       `json:"hostname"`
	Name           *string       `json:"name"`
	GID            *int64        `json:"gid"`
	Members        []GroupMember `json:"members"`
	Description    *string       `json:"description"`
}

// UserGroupScanResult is the top-level user-group scan output.
type UserGroupScanResult struct {
	Total int             `json:"total"`
	Rows  []UserGroupInfo `json:"rows"`
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
