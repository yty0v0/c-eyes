//go:build windows

package benchmark

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type windowsSecurityPolicyData struct {
	SystemAccess    map[string]string
	EventAudit      map[string]string
	RegistryValues  map[string]string
	PrivilegeRights map[string][]string
}

func (s *windowsBenchmarkCollectorState) securityPolicy(ctx context.Context) (*windowsSecurityPolicyData, error) {
	if s.policy != nil {
		return s.policy, nil
	}
	policy, err := collectWindowsSecurityPolicy(ctx)
	if err != nil {
		return nil, err
	}
	s.policy = policy
	return policy, nil
}

func collectWindowsSecurityPolicy(ctx context.Context) (*windowsSecurityPolicyData, error) {
	workDir, err := os.MkdirTemp("", "c-eyes-benchmark-secpol-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	cfgPath := filepath.Join(workDir, "security-policy.inf")
	cmd := exec.CommandContext(ctx, "secedit", "/export", "/cfg", cfgPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("secedit export failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	policy := &windowsSecurityPolicyData{
		SystemAccess:    map[string]string{},
		EventAudit:      map[string]string{},
		RegistryValues:  map[string]string{},
		PrivilegeRights: map[string][]string{},
	}

	payload, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}
	text := string(payload)
	if decoded, ok := decodeUTF16WithBOM(payload); ok {
		text = strings.TrimPrefix(decoded, "\ufeff")
	} else if decoded, ok := decodeUTF16LEHeuristic(payload); ok {
		text = strings.TrimPrefix(decoded, "\ufeff")
	}

	section := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch section {
		case "System Access":
			policy.SystemAccess[key] = trimPolicyValue(val)
		case "Event Audit":
			policy.EventAudit[key] = trimPolicyValue(val)
		case "Registry Values":
			regKey, regVal := parseRegistryPolicyValue(key, val)
			if regKey != "" {
				policy.RegistryValues[regKey] = regVal
			}
		case "Privilege Rights":
			policy.PrivilegeRights[key] = parsePrivilegeRightsValue(val)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return policy, nil
}

func trimPolicyValue(value string) string {
	trimmed := strings.TrimSpace(value)
	trimmed = strings.Trim(trimmed, `"`)
	return trimmed
}

func parseRegistryPolicyValue(key, value string) (string, string) {
	trimmedKey := strings.TrimSpace(key)
	trimmedValue := strings.TrimSpace(value)
	if trimmedKey == "" {
		return "", ""
	}
	if idx := strings.Index(trimmedValue, ","); idx >= 0 {
		trimmedValue = strings.TrimSpace(trimmedValue[idx+1:])
	}
	trimmedValue = strings.Trim(trimmedValue, `"`)
	return trimmedKey, trimmedValue
}

func parsePrivilegeRightsValue(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.TrimPrefix(part, "*"))
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func collectWindowsPolicyCheck(ctx context.Context, state *windowsBenchmarkCollectorState, title, section, key string) (benchmarkCheckResult, error) {
	policy, err := state.securityPolicy(ctx)
	if err != nil {
		return benchmarkCheckResult{}, err
	}

	var value string
	switch section {
	case "system_access":
		value = policy.SystemAccess[key]
	case "event_audit":
		value = policy.EventAudit[key]
	case "registry":
		value = policy.RegistryValues[key]
	default:
		return benchmarkCheckResult{}, fmt.Errorf("unsupported policy section %q", section)
	}

	actual := fmt.Sprintf("%s=%s", title, value)
	evidence := mustMarshalPrettyJSON(map[string]any{
		"section": section,
		"key":     key,
		"value":   value,
	})
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: evidence,
		Eval: map[string]any{
			"value":     value,
			"int_value": parsePolicyInt(value),
		},
	}, nil
}

func collectWindowsPrivilegeMembershipCheck(ctx context.Context, state *windowsBenchmarkCollectorState, privilege, member string) (benchmarkCheckResult, error) {
	policy, err := state.securityPolicy(ctx)
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	items := policy.PrivilegeRights[privilege]
	contains := false
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(member)) {
			contains = true
			break
		}
	}
	actual := fmt.Sprintf("%s contains %s = %t", privilege, member, contains)
	evidence := mustMarshalPrettyJSON(map[string]any{
		"section": "privilege_rights",
		"key":     privilege,
		"items":   items,
	})
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: evidence,
		Eval: map[string]any{
			"contains_member": contains,
		},
	}, nil
}

func parsePolicyInt(value string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return n
}
