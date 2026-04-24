package riskanalysis

import "time"

// AnalysisMode controls which analysis paths are executed.
type AnalysisMode string

const (
	ModeLocalOnly AnalysisMode = "local_only"
	ModeCloudOnly AnalysisMode = "cloud_only"
	ModeFast      AnalysisMode = "fast"
	ModeSmart     AnalysisMode = "smart"
	ModeDeep      AnalysisMode = "deep"
	// ModeHybrid is kept as a backward-compatible alias and is normalized to ModeSmart.
	ModeHybrid AnalysisMode = "hybrid"
)

const (
	TargetTypeFile          = "file"
	TargetTypeProcess       = "process"
	TargetTypeProcessMemory = "process_memory"
)

// Hashes captures common file hashes used by the analyzer.
type Hashes struct {
	Sha256 string `json:"sha256,omitempty"`
	Md5    string `json:"md5,omitempty"`
	Sha1   string `json:"sha1,omitempty"`
}

// TargetMetadata describes the object under analysis.
type TargetMetadata struct {
	ScanID         string            `json:"scan_id"`
	Timestamp      time.Time         `json:"timestamp"`
	TargetType     string            `json:"target_type"`
	TargetPath     string            `json:"target_path"`
	SourceHostname string            `json:"-"`
	PID            *int              `json:"pid"`
	FileSize       *int64            `json:"file_size"`
	Hashes         Hashes            `json:"hashes"`
	Signature      SignatureMetadata `json:"signature,omitempty"`
	Process        ProcessMetadata   `json:"process,omitempty"`
	ProductName    string            `json:"product_name,omitempty"`
}

// SignatureMetadata describes code-signing attributes used in whitelist policy.
type SignatureMetadata struct {
	Valid      *bool  `json:"valid,omitempty"`
	Signer     string `json:"signer,omitempty"`
	Thumbprint string `json:"thumbprint,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
}

// ProcessMetadata carries process-chain context for policy matching.
type ProcessMetadata struct {
	Name       string `json:"name,omitempty"`
	Command    string `json:"command,omitempty"`
	ParentPID  *int   `json:"parent_pid,omitempty"`
	ParentName string `json:"parent_name,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`
}

// RiskAssessment summarizes the final weighted risk.
type RiskAssessment struct {
	AnalysisMode AnalysisMode `json:"analysis_mode"`
	RiskScore    float64      `json:"risk_score"`
	RiskLevel    string       `json:"risk_level"`
	Stage        string       `json:"stage,omitempty"`
}

// YaraRuleMatch captures a single YARA rule match.
type YaraRuleMatch struct {
	RuleName       string   `json:"rule_name"`
	Namespace      string   `json:"namespace,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Severity       int      `json:"severity"`
	MatchedStrings []string `json:"matched_strings,omitempty"`
}

// LocalAnalysis holds results from local YARA-X matching.
type LocalAnalysis struct {
	LocalMatched        bool            `json:"local_matched"`
	YaraResults         []YaraRuleMatch `json:"yara_results,omitempty"`
	LocalFallback       bool            `json:"local_fallback,omitempty"`
	LocalFallbackReason string          `json:"local_fallback_reason,omitempty"`
}

// CloudAnalysis holds results from cloud threat intel.
type CloudAnalysis struct {
	CloudQueried               bool               `json:"cloud_queried"`
	CloudProvider              string             `json:"cloud_provider,omitempty"`
	CloudProviders             []string           `json:"cloud_providers,omitempty"`
	Malicious                  int                `json:"malicious_votes,omitempty"`
	TotalEngines               int                `json:"total_engines,omitempty"`
	DetectionRate              string             `json:"detection_ratio,omitempty"`
	ThreatLabels               []string           `json:"threat_labels,omitempty"`
	CloudLink                  string             `json:"cloud_link,omitempty"`
	MaxProviderScore           float64            `json:"max_provider_score,omitempty"`
	EffectiveAverageScore      float64            `json:"effective_average_score,omitempty"`
	ProviderScoreCard          map[string]float64 `json:"provider_score_card,omitempty"`
	ProviderOutcomeCard        map[string]string  `json:"provider_outcome_card,omitempty"`
	ProviderErrorCard          map[string]string  `json:"provider_error_card,omitempty"`
	EffectiveProviderCount     int                `json:"effective_provider_count,omitempty"`
	ProviderSuccessCount       int                `json:"provider_success_count,omitempty"`
	ProviderNoResultCount      int                `json:"provider_no_result_count,omitempty"`
	ProviderFailedCount        int                `json:"provider_failed_count,omitempty"`
	ProviderTimeoutCount       int                `json:"provider_timeout_count,omitempty"`
	ProviderPendingCount       int                `json:"provider_pending_count,omitempty"`
	ProviderTotalCount         int                `json:"provider_total_count,omitempty"`
	LabelOverrideTriggered     bool               `json:"label_override_triggered,omitempty"`
	DetectionOverrideTriggered bool               `json:"detection_override_triggered,omitempty"`
	FailSafeTriggered          bool               `json:"fail_safe_triggered,omitempty"`
	FailSafeReason             string             `json:"fail_safe_reason,omitempty"`
}

// AnalysisResult is the final output record.
type AnalysisResult struct {
	ScanID                string             `json:"scan_id"`
	Timestamp             time.Time          `json:"timestamp"`
	TargetType            string             `json:"target_type"`
	TargetPath            string             `json:"target_path"`
	PID                   *int               `json:"pid"`
	FileSize              *int64             `json:"file_size"`
	Hashes                Hashes             `json:"hashes"`
	RiskAssessment        RiskAssessment     `json:"risk_assessment"`
	LocalAnalysis         *LocalAnalysis     `json:"local_analysis,omitempty"`
	CloudAnalysis         *CloudAnalysis     `json:"cloud_analysis,omitempty"`
	Whitelist             *WhitelistAnalysis `json:"whitelist_analysis,omitempty"`
	CloudUploadEnabled    bool               `json:"cloud_upload_enabled,omitempty"`
	CloudUploadAttempted  bool               `json:"cloud_upload_attempted,omitempty"`
	CloudUploadStatus     string             `json:"cloud_upload_status,omitempty"`
	CloudUploadReason     string             `json:"cloud_upload_reason,omitempty"`
	CloudUploadProviders  []string           `json:"cloud_upload_providers,omitempty"`
	CloudUploadTasks      []CloudUploadTask  `json:"cloud_upload_tasks,omitempty"`
	CloudUploadDurationMS int64              `json:"cloud_upload_duration_ms,omitempty"`
}

// AnalysisHints carries local context into staged cloud decisions.
type AnalysisHints struct {
	TargetType       string
	TargetPath       string
	LocalTags        []string
	LocalRuleNames   []string
	LocalSuspicious  bool
	HighConfidence   bool
	SuspiciousLabels int
}

// ScanRecord wraps a raw scan result entry.
type ScanRecord struct {
	Raw map[string]any
}

// WhitelistDecision describes whitelist engine outcomes.
type WhitelistDecision string

const (
	WhitelistDecisionAllow    WhitelistDecision = "allow"
	WhitelistDecisionDeny     WhitelistDecision = "deny"
	WhitelistDecisionContinue WhitelistDecision = "continue"
)

// WhitelistEvidence captures compact proof for a policy decision.
type WhitelistEvidence struct {
	Type  string `json:"type,omitempty"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// WhitelistAnalysis stores whitelist funnel verdict and evidence.
type WhitelistAnalysis struct {
	Checked    bool                `json:"checked"`
	Decision   WhitelistDecision   `json:"decision,omitempty"`
	Source     string              `json:"source,omitempty"`
	PolicyID   string              `json:"policy_id,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Confidence int                 `json:"confidence,omitempty"`
	Evidence   []WhitelistEvidence `json:"evidence,omitempty"`
	ExpiresAt  *time.Time          `json:"expires_at,omitempty"`
}
