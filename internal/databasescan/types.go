package databasescan

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// DatabaseScanParams defines filter inputs for database scan.
type DatabaseScanParams struct {
	Groups   []int64
	Hostname *string
	IP       *string
	Name     *string
	Versions []string
	Port     *int
	ConfPath *string
	LogPath  *string
	DataDir  *string
	Progress ProgressFunc
}

// DatabaseRecord is the normalized output row for database information collection.
type DatabaseRecord struct {
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
	Port           *int     `json:"port"`
	ProtoType      *string  `json:"protoType"`
	User           *string  `json:"user"`
	BindIP         *string  `json:"bindIp"`
	ConfPath       *string  `json:"confPath"`
	LogPath        *string  `json:"logPath"`
	DataDir        *string  `json:"dataDir"`
	PluginDir      *string  `json:"pluginDir"`
	Rest           *bool    `json:"rest"`
	Auth           *string  `json:"auth"`
	Web            *bool    `json:"web"`
	WebPort        *int     `json:"webPort"`
	WebAddress     *string  `json:"webAddress"`
	RegionServer   []string `json:"regionServer"`
	DBName         *string  `json:"dbName"`
	LoginModel     *int     `json:"loginModel"`
	AuditLevel     *int     `json:"auditLevel"`
	SysLogPath     *string  `json:"sysLogPath"`
	MainDBPath     *string  `json:"mainDbPath"`
}

// DatabaseScanResult is the top-level output.
type DatabaseScanResult struct {
	Total int              `json:"total"`
	Rows  []DatabaseRecord `json:"rows"`
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
