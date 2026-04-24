package main

import (
	"fmt"
	"time"

	"github.com/xuri/excelize/v2"

	"edrsystem/internal/riskanalysis"
)

var riskHeaders = []string{
	"scan_id",
	"timestamp",
	"target_type",
	"target_path",
	"pid",
	"file_size",
	"hashes.sha256",
	"hashes.md5",
	"hashes.sha1",
	"risk_assessment.analysis_mode",
	"risk_assessment.risk_score",
	"risk_assessment.risk_level",
	"local_analysis.local_matched",
	"local_analysis.local_fallback",
	"local_analysis.local_fallback_reason",
	"local_analysis.yara_results",
	"cloud_analysis.cloud_queried",
	"cloud_analysis.cloud_provider",
	"cloud_analysis.cloud_providers",
	"cloud_analysis.malicious_votes",
	"cloud_analysis.total_engines",
	"cloud_analysis.detection_ratio",
	"cloud_analysis.threat_labels",
	"cloud_analysis.cloud_link",
	"cloud_analysis.max_provider_score",
	"cloud_analysis.provider_score_card",
	"cloud_upload_enabled",
	"cloud_upload_attempted",
	"cloud_upload_status",
	"cloud_upload_reason",
	"cloud_upload_providers",
	"cloud_upload_tasks",
	"cloud_upload_duration_ms",
	"whitelist_analysis.checked",
	"whitelist_analysis.decision",
	"whitelist_analysis.source",
	"whitelist_analysis.policy_id",
	"whitelist_analysis.reason",
	"whitelist_analysis.confidence",
	"whitelist_analysis.evidence",
	"whitelist_analysis.expires_at",
}

func writeRiskExcel(path string, results []riskanalysis.AnalysisResult) error {
	if path == "" {
		return fmt.Errorf("excel 输出路径不能为空")
	}

	file := excelize.NewFile()
	defer func() { _ = file.Close() }()

	sheet := "risk_analysis"
	file.SetSheetName("Sheet1", sheet)

	for i, header := range riskHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = file.SetCellValue(sheet, cell, header)
	}

	for r, result := range results {
		row := r + 2
		values := riskExcelRow(result)
		for c, value := range values {
			cell, _ := excelize.CoordinatesToCellName(c+1, row)
			_ = file.SetCellValue(sheet, cell, value)
		}
	}

	return file.SaveAs(path)
}

func riskExcelRow(result riskanalysis.AnalysisResult) []any {
	var (
		pid      *int
		fileSize *int64
		score    *float64
	)
	pid = result.PID
	fileSize = result.FileSize
	score = &result.RiskAssessment.RiskScore

	var (
		localMatched        *bool
		localFallback       *bool
		localFallbackReason *string
		localResults        any
	)
	if result.LocalAnalysis != nil {
		localMatched = &result.LocalAnalysis.LocalMatched
		localFallback = &result.LocalAnalysis.LocalFallback
		if result.LocalAnalysis.LocalFallbackReason != "" {
			localFallbackReason = &result.LocalAnalysis.LocalFallbackReason
		}
		localResults = result.LocalAnalysis.YaraResults
	}

	var (
		cloudQueried      *bool
		cloudProvider     *string
		cloudProviders    any
		malicious         *int
		totalEngines      *int
		detection         *string
		labels            any
		cloudLink         *string
		maxProviderScore  *float64
		providerScoreCard any
	)
	if result.CloudAnalysis != nil {
		cloudQueried = &result.CloudAnalysis.CloudQueried
		if result.CloudAnalysis.CloudProvider != "" {
			cloudProvider = &result.CloudAnalysis.CloudProvider
		}
		if len(result.CloudAnalysis.CloudProviders) > 0 {
			cloudProviders = result.CloudAnalysis.CloudProviders
		}
		malicious = &result.CloudAnalysis.Malicious
		totalEngines = &result.CloudAnalysis.TotalEngines
		if result.CloudAnalysis.DetectionRate != "" {
			detection = &result.CloudAnalysis.DetectionRate
		}
		labels = result.CloudAnalysis.ThreatLabels
		if result.CloudAnalysis.CloudLink != "" {
			cloudLink = &result.CloudAnalysis.CloudLink
		}
		if result.CloudAnalysis.MaxProviderScore > 0 {
			maxProviderScore = &result.CloudAnalysis.MaxProviderScore
		}
		if len(result.CloudAnalysis.ProviderScoreCard) > 0 {
			providerScoreCard = result.CloudAnalysis.ProviderScoreCard
		}
	}

	var (
		whitelistChecked    *bool
		whitelistDecision   *string
		whitelistSource     *string
		whitelistPolicyID   *string
		whitelistReason     *string
		whitelistConfidence *int
		whitelistEvidence   any
		whitelistExpiresAt  *string
	)
	if result.Whitelist != nil {
		whitelistChecked = &result.Whitelist.Checked
		if result.Whitelist.Decision != "" {
			val := string(result.Whitelist.Decision)
			whitelistDecision = &val
		}
		if result.Whitelist.Source != "" {
			whitelistSource = &result.Whitelist.Source
		}
		if result.Whitelist.PolicyID != "" {
			whitelistPolicyID = &result.Whitelist.PolicyID
		}
		if result.Whitelist.Reason != "" {
			whitelistReason = &result.Whitelist.Reason
		}
		if result.Whitelist.Confidence != 0 {
			whitelistConfidence = &result.Whitelist.Confidence
		}
		if len(result.Whitelist.Evidence) > 0 {
			whitelistEvidence = result.Whitelist.Evidence
		}
		if result.Whitelist.ExpiresAt != nil {
			val := result.Whitelist.ExpiresAt.Format(time.RFC3339)
			whitelistExpiresAt = &val
		}
	}

	return []any{
		result.ScanID,
		timeVal(&result.Timestamp),
		result.TargetType,
		result.TargetPath,
		intVal(pid),
		int64Val(fileSize),
		result.Hashes.Sha256,
		result.Hashes.Md5,
		result.Hashes.Sha1,
		string(result.RiskAssessment.AnalysisMode),
		float64Val(score),
		result.RiskAssessment.RiskLevel,
		boolVal(localMatched),
		boolVal(localFallback),
		stringVal(localFallbackReason),
		jsonCell(localResults),
		boolVal(cloudQueried),
		stringVal(cloudProvider),
		jsonCell(cloudProviders),
		intVal(malicious),
		intVal(totalEngines),
		stringVal(detection),
		jsonCell(labels),
		stringVal(cloudLink),
		float64Val(maxProviderScore),
		jsonCell(providerScoreCard),
		result.CloudUploadEnabled,
		result.CloudUploadAttempted,
		result.CloudUploadStatus,
		result.CloudUploadReason,
		jsonCell(result.CloudUploadProviders),
		jsonCell(result.CloudUploadTasks),
		result.CloudUploadDurationMS,
		boolVal(whitelistChecked),
		stringVal(whitelistDecision),
		stringVal(whitelistSource),
		stringVal(whitelistPolicyID),
		stringVal(whitelistReason),
		intVal(whitelistConfidence),
		jsonCell(whitelistEvidence),
		stringVal(whitelistExpiresAt),
	}
}
