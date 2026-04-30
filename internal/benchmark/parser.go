package benchmark

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

type baselineXML struct {
	XMLName  xml.Name     `xml:"result"`
	UUID     string       `xml:"uuid,attr"`
	IP       string       `xml:"ip,attr"`
	Time     string       `xml:"template_time,attr"`
	Security []xmlSection `xml:"security"`
}

type xmlSection struct {
	Type  string    `xml:"type,attr"`
	Items []xmlItem `xml:"item"`
}

type xmlItem struct {
	Flag string `xml:"flag,attr"`
	Cmd  xmlCmd `xml:"cmd"`
}

type xmlCmd struct {
	Info    string `xml:"info,attr"`
	Command string `xml:"command"`
	Value   string `xml:"value"`
}

func parseXMLFile(path string, template Template) ([]Row, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var parsed baselineXML
	if err := xml.Unmarshal(payload, &parsed); err != nil {
		return nil, fmt.Errorf("parse benchmark xml failed: %w", err)
	}

	host := strings.TrimSpace(parsed.IP)
	ruleIndex := map[string]benchmarkRule{}
	if rules, err := loadBenchmarkRuleSet(template); err == nil {
		ruleIndex = buildBenchmarkRuleIndex(rules)
	}
	rows := make([]Row, 0, 64)
	for _, section := range parsed.Security {
		category := strings.TrimSpace(section.Type)
		for idx, item := range section.Items {
			checkID := strings.TrimSpace(item.Flag)
			if checkID == "" {
				checkID = fmt.Sprintf("%s-%d", category, idx+1)
			}

			command := strings.TrimSpace(item.Cmd.Command)
			actual := strings.TrimSpace(item.Cmd.Value)
			assessment := deriveStatusAssessment(template, checkID, actual)

			result := benchmarkCheckResult{
				ID:          checkID,
				SectionType: category,
				Command:     command,
				Actual:      actual,
				Evidence:    actual,
				Eval: map[string]any{
					"actual": actual,
				},
				Status: assessment,
			}
			if rule, ok := ruleIndex[checkID]; ok {
				applyBenchmarkRule(rule, &result)
			}
			row := Row{
				Host:            host,
				Template:        string(template),
				CheckID:         checkID,
				CheckName:       firstNonEmpty(result.Name, checkID),
				Category:        firstNonEmpty(result.Category, category),
				Description:     result.Description,
				Status:          result.Status.Status,
				Evaluated:       result.Status.Evaluated,
				StatusReason:    result.Status.StatusReason,
				ExecutionStatus: result.Status.ExecutionStatus,
				Severity:        result.Severity,
				Recommendation:  result.Recommendation,
				Expected:        result.Expected,
				Actual:          result.Actual,
				Evidence:        result.Evidence,
				Command:         result.Command,
			}
			rows = append(rows, row)
		}
	}

	// If script generated no item blocks, keep one diagnostic row for visibility.
	if len(rows) == 0 {
		rows = append(rows, Row{
			Host:            host,
			Template:        string(template),
			CheckID:         "no-item",
			CheckName:       "no-item",
			Category:        "meta",
			Status:          "unknown",
			Evaluated:       false,
			StatusReason:    "undetermined",
			ExecutionStatus: "ok",
			Actual:          "no benchmark items found in raw xml",
			Evidence:        "no benchmark items found in raw xml",
		})
	}

	return rows, nil
}

func deriveStatus(template Template, checkID, value string) string {
	return deriveStatusAssessment(template, checkID, value).Status
}

type statusAssessment struct {
	Status          string
	Evaluated       bool
	StatusReason    string
	ExecutionStatus string
}

func deriveStatusAssessment(template Template, checkID, value string) statusAssessment {
	if assessment, ok := deriveStatusAssessmentByTemplateRule(template, checkID, value); ok {
		return assessment
	}

	v := normalizeLowerTrim(value)
	if v == "" {
		return statusAssessment{
			Status:          "unknown",
			Evaluated:       false,
			StatusReason:    "undetermined",
			ExecutionStatus: "ok",
		}
	}

	if containsAnyPhrase(v, informationalExecutionFailureHints) {
		return statusAssessment{
			Status:          "fail",
			Evaluated:       true,
			StatusReason:    "execution_error",
			ExecutionStatus: "error",
		}
	}

	passHints := []string{
		"pass",
		"passed",
		"ok",
		"enabled",
		"running",
		"allntfs",
		"compliant",
		"success",
	}
	if containsAnyStatusToken(v, passHints) {
		return statusAssessment{
			Status:          "pass",
			Evaluated:       true,
			ExecutionStatus: "ok",
		}
	}

	failHints := []string{
		"fail",
		"failed",
		"disabled",
		"error",
		"denied",
		"non-compliant",
		"everyone",
		"unsafe",
	}
	if containsAnyStatusToken(v, failHints) {
		return statusAssessment{
			Status:          "fail",
			Evaluated:       true,
			ExecutionStatus: "ok",
		}
	}

	return statusAssessment{
		Status:          "unknown",
		Evaluated:       false,
		StatusReason:    "undetermined",
		ExecutionStatus: "ok",
	}
}

func summarize(rows []Row) Summary {
	summary := Summary{Total: len(rows)}
	for _, row := range rows {
		status := normalizeLowerTrim(row.Status)
		switch status {
		case "pass":
			summary.Pass++
		case "fail":
			summary.Fail++
		default:
			summary.Unknown++
		}

		if row.Evaluated || status == "pass" || status == "fail" {
			summary.Evaluated++
		}
	}

	if summary.Evaluated > 0 {
		summary.ComplianceRate = float64(summary.Pass) / float64(summary.Evaluated)
	}
	if summary.Total > 0 {
		summary.CoverageRate = float64(summary.Evaluated) / float64(summary.Total)
		summary.UnknownRate = float64(summary.Unknown) / float64(summary.Total)
	}
	return summary
}
