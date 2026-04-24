package accountscan

import "time"

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// DateRange filters values within [From, To].
type DateRange struct {
	From *time.Time
	To   *time.Time
}

// AccountScanParams defines filter inputs for account scan.
type AccountScanParams struct {
	Groups        []int64
	Hostname      *string
	IP            *string
	Status        []int
	Name          *string
	Home          *string
	LastLoginTime *DateRange
	GID           *int64
	UID           *int64
	Progress      ProgressFunc
}

// SudoAccess represents a sudo access entry.
type SudoAccess struct {
	Shell *string `json:"shell"`
	User  *string `json:"user"`
}

// AuthorizedKey represents one authorized key line.
type AuthorizedKey struct {
	EncryptType *string `json:"encryptType"`
	Comment     *string `json:"comment"`
	Value       *string `json:"value"`
	MD5         *string `json:"md5"`
}

// AccountInfo is the normalized account output record.
type AccountInfo struct {
	DisplayIP            *string         `json:"displayIp"`
	ConnectionIP         *string         `json:"connectionIp"`
	ExternalIPList       []string        `json:"externalIpList"`
	InternalIPList       []string        `json:"internalIpList"`
	BizGroupID           *int64          `json:"bizGroupId"`
	BizGroup             *string         `json:"bizGroup"`
	Remark               *string         `json:"remark"`
	HostTagList          []string        `json:"hostTagList"`
	Hostname             *string         `json:"hostname"`
	UID                  *int64          `json:"uid"`
	GID                  *int64          `json:"gid"`
	Groups               []string        `json:"groups"`
	Name                 *string         `json:"name"`
	Status               *int            `json:"status"`
	Home                 *string         `json:"home"`
	Shell                *string         `json:"shell"`
	LoginStatus          *int            `json:"loginStatus"`
	LastLoginTime        *time.Time      `json:"lastLoginTime"`
	PwdMaxDays           *int            `json:"pwdMaxDays"`
	PwdMinDays           *int            `json:"pwdMinDays"`
	PwdWarnDays          *int            `json:"pwdWarnDays"`
	SSHACL               *string         `json:"sshAcl"`
	Comment              *string         `json:"comment"`
	LastLoginTTY         *string         `json:"lastLoginTty"`
	LastLoginIP          *string         `json:"lastLoginIp"`
	ExpireTime           *time.Time      `json:"expireTime"`
	Expired              *bool           `json:"expired"`
	FullName             *string         `json:"fullName"`
	SudoAccesses         []SudoAccess    `json:"sudoAccesses"`
	Root                 *bool           `json:"root"`
	Description          *string         `json:"description"`
	Type                 *int            `json:"type"`
	LastChangPwdTime     *time.Time      `json:"lastChangPwdTime"`
	AccountLoginType     *int            `json:"accountLoginType"`
	InteractiveLoginType *int            `json:"interactiveLoginType"`
	PasswordInactiveDays *int            `json:"passwordInactiveDays"`
	Sudo                 *bool           `json:"sudo"`
	AuthorizedKeys       []AuthorizedKey `json:"authorizedKeys"`
}

// AccountScanResult is the top-level account scan output.
type AccountScanResult struct {
	Total int           `json:"total"`
	Rows  []AccountInfo `json:"rows"`
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
