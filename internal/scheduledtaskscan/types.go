package scheduledtaskscan

import "time"

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// DateRange filters values within [From, To].
type DateRange struct {
	From *time.Time
	To   *time.Time
}

// ScheduledTaskScanParams defines filter inputs for scheduled task scan.
type ScheduledTaskScanParams struct {
	Groups   []int64
	Hostname *string
	IP       *string
	User     []string
	ExecPath *string
	Conf     *string
	TaskTime *DateRange
	TaskType []string
	Progress ProgressFunc
}

// ScheduledTaskInfo is the normalized scheduled task output record.
type ScheduledTaskInfo struct {
	DisplayIP      *string    `json:"displayIp"`
	ExternalIPList []string   `json:"externalIpList"`
	InternalIPList []string   `json:"internalIpList"`
	BizGroupID     *int64     `json:"bizGroupId"`
	BizGroup       *string    `json:"bizGroup"`
	Remark         *string    `json:"remark"`
	HostTagList    []string   `json:"hostTagList"`
	Hostname       *string    `json:"hostname"`
	User           *string    `json:"user"`
	ExecTime       *string    `json:"execTime"`
	ExecPath       *string    `json:"execPath"`
	Conf           *string    `json:"conf"`
	TaskTime       *time.Time `json:"taskTime"`
	TaskID         *int64     `json:"taskId"`
	TaskType       *string    `json:"taskType"`
	CrondOpen      *bool      `json:"crondOpen"`
}

// ScheduledTaskScanResult is the top-level output.
type ScheduledTaskScanResult struct {
	Total int                 `json:"total"`
	Rows  []ScheduledTaskInfo `json:"rows"`
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
