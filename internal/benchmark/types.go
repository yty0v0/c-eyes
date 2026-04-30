package benchmark

import "fmt"

type Template string

const (
	TemplateAuto    Template = "auto"
	TemplateWindows Template = "windows"
	TemplateLinux   Template = "linux"
	TemplateEulerOS Template = "euleros"
	TemplateKylin   Template = "kylin"
)

var validTemplates = map[Template]struct{}{
	TemplateAuto:    {},
	TemplateWindows: {},
	TemplateLinux:   {},
	TemplateEulerOS: {},
	TemplateKylin:   {},
}

func NormalizeTemplate(raw string) (Template, error) {
	t := Template(normalizeLowerTrim(raw))
	if t == "" {
		t = TemplateAuto
	}
	if _, ok := validTemplates[t]; !ok {
		return "", fmt.Errorf("invalid argument: --template only supports auto|windows|linux|euleros|kylin")
	}
	return t, nil
}

type ScanOptions struct {
	Template Template
	Progress func(done, total int, stage string)
}

type Summary struct {
	Total          int     `json:"total"`
	Pass           int     `json:"pass"`
	Fail           int     `json:"fail"`
	Unknown        int     `json:"unknown"`
	Evaluated      int     `json:"evaluated"`
	ComplianceRate float64 `json:"compliance_rate"`
	CoverageRate   float64 `json:"coverage_rate"`
	UnknownRate    float64 `json:"unknown_rate"`
}

type Metadata struct {
	UUID            string `json:"uuid,omitempty"`
	TemplateTime    string `json:"template_time,omitempty"`
	Product         string `json:"product,omitempty"`
	TemplateName    string `json:"template_name,omitempty"`
	TemplateVersion string `json:"template_version,omitempty"`
	Industry        string `json:"industry,omitempty"`
	SystemVersion   string `json:"system_version,omitempty"`
	Hash            string `json:"hash,omitempty"`
}

type Row struct {
	Host            string `json:"host,omitempty"`
	Template        string `json:"template"`
	CheckID         string `json:"check_id"`
	CheckName       string `json:"check_name,omitempty"`
	Category        string `json:"category,omitempty"`
	Description     string `json:"description,omitempty"`
	Status          string `json:"status"`
	Evaluated       bool   `json:"evaluated"`
	StatusReason    string `json:"status_reason,omitempty"`
	ExecutionStatus string `json:"execution_status,omitempty"`
	Severity        string `json:"severity,omitempty"`
	Recommendation  string `json:"recommendation,omitempty"`
	Expected        string `json:"expected,omitempty"`
	Actual          string `json:"actual,omitempty"`
	Evidence        string `json:"evidence,omitempty"`
	Command         string `json:"command,omitempty"`
}

type ScanResult struct {
	Template string   `json:"template"`
	Metadata Metadata `json:"metadata,omitempty"`
	Summary  Summary  `json:"summary"`
	Rows     []Row    `json:"rows"`
}
