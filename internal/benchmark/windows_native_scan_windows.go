//go:build windows

package benchmark

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"edrsystem/internal/accountscan"
	"edrsystem/internal/processscan"
	"edrsystem/internal/startupscan"
	"edrsystem/internal/usergroupscan"

	"golang.org/x/sys/windows/registry"
)

type windowsBenchmarkCollectorState struct {
	hostInfo *processscan.HostInfo
	policy   *windowsSecurityPolicyData

	userAccounts []windowsUserAccountRecord
	groupDetails []windowsGroupRecord
	serviceRows  []windowsServiceRecord
	services     []*startupscan.StartupInfo
	process      []*processscan.ProcessInfo

	startupRows     []windowsStartupCommandRecord
	startupCommands []windowsStartupCommandEntry
	connections     []windowsNetConnection
	shares          []windowsShareInfo
	hotfixes        []windowsHotfixInfo
}

type windowsStartupCommandEntry struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
}

type windowsOSInfo struct {
	ProductName        string `json:"product_name"`
	DisplayVersion     string `json:"display_version,omitempty"`
	ReleaseID          string `json:"release_id,omitempty"`
	CurrentVersion     string `json:"current_version,omitempty"`
	CurrentBuildNumber string `json:"current_build_number,omitempty"`
	UBR                uint64 `json:"ubr,omitempty"`
	CSDVersion         string `json:"csd_version,omitempty"`
}

type windowsTimezoneInfo struct {
	KeyName      string `json:"key_name"`
	DisplayName  string `json:"display_name,omitempty"`
	StandardName string `json:"standard_name,omitempty"`
	DaylightName string `json:"daylight_name,omitempty"`
	BiasMinutes  int32  `json:"bias_minutes"`
}

type windowsHotfixInfo struct {
	HotFixID     string `json:"hotfix_id"`
	Source       string `json:"source,omitempty"`
	InstalledOn  string `json:"installed_on,omitempty"`
	InstalledBy  string `json:"installed_by,omitempty"`
	Description  string `json:"description,omitempty"`
	PackageState uint64 `json:"package_state,omitempty"`
}

type windowsFirewallProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type windowsFirewallInfo struct {
	Profiles []windowsFirewallProfile `json:"profiles"`
	Enabled  bool                     `json:"enabled"`
}

type windowsFilesystemInfo struct {
	AllNTFS bool                 `json:"all_ntfs"`
	Drives  []windowsDriveRecord `json:"drives"`
}

type windowsDriveRecord struct {
	Name       string `json:"name"`
	FileSystem string `json:"file_system"`
	DriveType  uint32 `json:"drive_type"`
}

type windowsAntivirusInfo struct {
	Detected               bool     `json:"detected"`
	SecurityCenterProducts []string `json:"security_center_products"`
	ProductHints           []string `json:"product_hints"`
	ServiceIndicators      []string `json:"service_indicators"`
	ProcessIndicators      []string `json:"process_indicators"`
}

type windowsTemplateMetadata struct {
	Product         string
	TemplateName    string
	TemplateVersion string
	Industry        string
	SystemVersion   string
	Hash            string
}

type windowsBenchmarkCollectorSpec struct {
	ID          string
	SectionType string
	Command     string
	Collect     func(context.Context, *windowsBenchmarkCollectorState) (benchmarkCheckResult, error)
}

func scanWindowsNativeBenchmark(ctx context.Context, template Template, workingRoot string, progress func(done, total int, stage string)) (ScanResult, bool, error) {
	if template != TemplateWindows {
		return ScanResult{}, false, nil
	}

	ruleSet, err := loadBenchmarkRuleSet(template)
	if err != nil {
		return ScanResult{}, true, err
	}
	ruleIndex := buildBenchmarkRuleIndex(ruleSet)

	state, err := newWindowsBenchmarkCollectorState()
	if err != nil {
		return ScanResult{}, true, err
	}

	specs := windowsBenchmarkCollectorSpecs()
	results := make([]benchmarkCheckResult, 0, len(specs))
	for idx, spec := range specs {
		select {
		case <-ctx.Done():
			return ScanResult{}, true, ctx.Err()
		default:
		}

		notifyProgress(progress, benchmarkRangedProgress(benchmarkProgressExecuteStart, benchmarkProgressExecuteEnd, idx+1, len(specs)), benchmarkProgressTotalSteps, "execute checks")

		result, err := spec.Collect(ctx, state)
		result.ID = spec.ID
		result.SectionType = firstNonEmpty(spec.SectionType, result.SectionType, "display")
		result.Command = firstNonEmpty(spec.Command, result.Command)

		if err != nil {
			message := fmt.Sprintf("collector execution failed: %v", err)
			if strings.TrimSpace(result.Actual) == "" {
				result.Actual = message
			}
			if strings.TrimSpace(result.Evidence) == "" {
				result.Evidence = message
			}
			result.Status = statusAssessment{
				Status:          "fail",
				Evaluated:       true,
				StatusReason:    "execution_error",
				ExecutionStatus: "error",
			}
		}

		if rule, ok := ruleIndex[spec.ID]; ok {
			applyBenchmarkRule(rule, &result)
		} else if result.Status == (statusAssessment{}) {
			result.Status = statusAssessment{
				Status:          "unknown",
				Evaluated:       false,
				StatusReason:    "rule_missing",
				ExecutionStatus: "ok",
			}
		}
		if result.Evidence == "" {
			result.Evidence = result.Actual
		}
		if result.Actual == "" {
			result.Actual = result.Evidence
		}
		if result.Status.ExecutionStatus == "" {
			result.Status.ExecutionStatus = "ok"
		}
		results = append(results, result)
	}

	notifyProgress(progress, benchmarkProgressCollectDone, benchmarkProgressTotalSteps, "assemble results")
	rows := make([]Row, 0, len(results))
	for _, result := range results {
		rows = append(rows, Row{
			Host:            firstNonEmpty(state.hostName(), state.hostIP()),
			Template:        string(template),
			CheckID:         result.ID,
			CheckName:       firstNonEmpty(result.Name, result.ID),
			Category:        result.Category,
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
		})
	}
	notifyProgress(progress, benchmarkProgressParseEnd, benchmarkProgressTotalSteps, "finalize results")

	return ScanResult{
		Template: string(template),
		Metadata: Metadata{
			UUID:            profileUUIDForTemplate(template),
			TemplateTime:    profileTimeForTemplate(template),
			Product:         windowsTemplateInfo.Product,
			TemplateName:    windowsTemplateInfo.TemplateName,
			TemplateVersion: windowsTemplateInfo.TemplateVersion,
			Industry:        windowsTemplateInfo.Industry,
			SystemVersion:   windowsTemplateInfo.SystemVersion,
			Hash:            windowsTemplateInfo.Hash,
		},
		Summary: summarize(rows),
		Rows:    rows,
	}, true, nil
}

func newWindowsBenchmarkCollectorState() (*windowsBenchmarkCollectorState, error) {
	hostInfo, err := processscan.GetHostInfo()
	if err != nil {
		return nil, err
	}
	return &windowsBenchmarkCollectorState{hostInfo: &hostInfo}, nil
}

func (s *windowsBenchmarkCollectorState) hostIP() string {
	if s == nil || s.hostInfo == nil {
		return ""
	}
	if s.hostInfo.DisplayIP != nil {
		return strings.TrimSpace(*s.hostInfo.DisplayIP)
	}
	if len(s.hostInfo.InternalIPs) > 0 {
		return strings.TrimSpace(s.hostInfo.InternalIPs[0])
	}
	if len(s.hostInfo.ExternalIPs) > 0 {
		return strings.TrimSpace(s.hostInfo.ExternalIPs[0])
	}
	return ""
}

func (s *windowsBenchmarkCollectorState) hostName() string {
	if s == nil || s.hostInfo == nil {
		return ""
	}
	return strings.TrimSpace(s.hostInfo.Hostname)
}

func windowsBenchmarkCollectorSpecs() []windowsBenchmarkCollectorSpec {
	return []windowsBenchmarkCollectorSpec{
		{ID: "W-FW-001", SectionType: "auto", Command: "native/windows/firewall_policy", Collect: collectWindowsFirewallCheck},
		{ID: "W-AV-001", SectionType: "auto", Command: "native/windows/antivirus_presence", Collect: collectWindowsAntivirusCheck},
		{ID: "W-FS-001", SectionType: "auto", Command: "native/windows/fixed_drive_filesystems", Collect: collectWindowsFilesystemCheck},
		{ID: "W-SHARE-001", SectionType: "auto", Command: "native/windows/share_permissions", Collect: collectWindowsEveryoneShareCheck},
		{ID: "W-PASS-001", SectionType: "auto", Command: "native/windows/security_policy/System Access/MinimumPasswordLength", Collect: collectWindowsMinimumPasswordLengthCheck},
		{ID: "W-PASS-002", SectionType: "auto", Command: "native/windows/security_policy/System Access/PasswordComplexity", Collect: collectWindowsPasswordComplexityCheck},
		{ID: "W-PASS-003", SectionType: "auto", Command: "native/windows/security_policy/System Access/PasswordHistorySize", Collect: collectWindowsPasswordHistoryCheck},
		{ID: "W-PASS-004", SectionType: "auto", Command: "native/windows/security_policy/System Access/MaximumPasswordAge", Collect: collectWindowsMaximumPasswordAgeCheck},
		{ID: "W-PASS-006", SectionType: "auto", Command: "native/windows/security_policy/System Access/MinimumPasswordAge", Collect: collectWindowsMinimumPasswordAgeCheck},
		{ID: "W-LOCK-001", SectionType: "auto", Command: "native/windows/security_policy/System Access/LockoutBadCount", Collect: collectWindowsLockoutBadCountCheck},
		{ID: "W-LOCK-002", SectionType: "auto", Command: "native/windows/security_policy/System Access/AllowAdministratorLockout", Collect: collectWindowsAllowAdministratorLockoutCheck},
		{ID: "W-LOCK-003", SectionType: "auto", Command: "native/windows/security_policy/System Access/ResetLockoutCount", Collect: collectWindowsResetLockoutCountCheck},
		{ID: "W-LOCK-004", SectionType: "auto", Command: "native/windows/security_policy/System Access/LockoutDuration", Collect: collectWindowsLockoutDurationCheck},
		{ID: "W-ACC-002", SectionType: "auto", Command: "native/windows/security_policy/System Access/EnableGuestAccount", Collect: collectWindowsGuestAccountDisabledCheck},
		{ID: "W-ACC-003", SectionType: "auto", Command: "native/windows/security_policy/System Access/NewAdministratorName", Collect: collectWindowsAdministratorRenameCheck},
		{ID: "W-ACC-004", SectionType: "auto", Command: "native/windows/security_policy/System Access/NewGuestName", Collect: collectWindowsGuestRenameCheck},
		{ID: "W-PASS-005", SectionType: "auto", Command: "native/windows/security_policy/Registry/LimitBlankPasswordUse", Collect: collectWindowsBlankPasswordRestrictionCheck},
		{ID: "W-PASS-007", SectionType: "auto", Command: "native/windows/security_policy/System Access/ClearTextPassword", Collect: collectWindowsClearTextPasswordCheck},
		{ID: "W-AUDIT-001", SectionType: "auto", Command: "native/windows/security_policy/Event Audit/AuditLogonEvents", Collect: collectWindowsAuditLogonEventsCheck},
		{ID: "W-AUDIT-002", SectionType: "auto", Command: "native/windows/security_policy/Event Audit/AuditAccountLogon", Collect: collectWindowsAuditAccountLogonCheck},
		{ID: "W-AUDIT-003", SectionType: "auto", Command: "native/windows/security_policy/Event Audit/AuditSystemEvents", Collect: collectWindowsAuditSystemEventsCheck},
		{ID: "W-AUDIT-004", SectionType: "auto", Command: "native/windows/security_policy/Event Audit/AuditPolicyChange", Collect: collectWindowsAuditPolicyChangeCheck},
		{ID: "W-AUDIT-005", SectionType: "auto", Command: "native/windows/security_policy/Event Audit/AuditAccountManage", Collect: collectWindowsAuditAccountManageCheck},
		{ID: "W-UAC-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableLUA", Collect: collectWindowsEnableLUACheck},
		{ID: "W-UAC-002", SectionType: "auto", Command: "native/windows/security_policy/Registry/FilterAdministratorToken", Collect: collectWindowsFilterAdministratorTokenCheck},
		{ID: "W-UAC-003", SectionType: "auto", Command: "native/windows/security_policy/Registry/PromptOnSecureDesktop", Collect: collectWindowsPromptOnSecureDesktopCheck},
		{ID: "W-UAC-004", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableInstallerDetection", Collect: collectWindowsEnableInstallerDetectionCheck},
		{ID: "W-UAC-005", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableSecureUIAPaths", Collect: collectWindowsEnableSecureUIAPathsCheck},
		{ID: "W-UAC-006", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableVirtualization", Collect: collectWindowsEnableVirtualizationCheck},
		{ID: "W-UAC-007", SectionType: "auto", Command: "native/windows/security_policy/Registry/ConsentPromptBehaviorAdmin", Collect: collectWindowsConsentPromptBehaviorAdminCheck},
		{ID: "W-UAC-008", SectionType: "auto", Command: "native/windows/security_policy/Registry/ConsentPromptBehaviorUser", Collect: collectWindowsConsentPromptBehaviorUserCheck},
		{ID: "W-LOGON-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/DontDisplayLastUserName", Collect: collectWindowsDontDisplayLastUserNameCheck},
		{ID: "W-LOGON-002", SectionType: "auto", Command: "native/windows/security_policy/Registry/ShutdownWithoutLogon", Collect: collectWindowsShutdownWithoutLogonCheck},
		{ID: "W-LOGON-003", SectionType: "auto", Command: "native/windows/security_policy/Registry/CachedLogonsCount", Collect: collectWindowsCachedLogonsCountCheck},
		{ID: "W-SMB-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/RestrictNullSessAccess", Collect: collectWindowsRestrictNullSessionCheck},
		{ID: "W-SMB-002", SectionType: "auto", Command: "native/windows/security_policy/Registry/NoLMHash", Collect: collectWindowsNoLMHashCheck},
		{ID: "W-SMB-003", SectionType: "auto", Command: "native/windows/security_policy/Registry/RestrictAnonymousSAM", Collect: collectWindowsRestrictAnonymousSAMCheck},
		{ID: "W-SMB-004", SectionType: "auto", Command: "native/windows/security_policy/Registry/EveryoneIncludesAnonymous", Collect: collectWindowsEveryoneIncludesAnonymousCheck},
		{ID: "W-SMB-005", SectionType: "auto", Command: "native/windows/security_policy/System Access/LSAAnonymousNameLookup", Collect: collectWindowsLSAAnonymousNameLookupCheck},
		{ID: "W-SMB-006", SectionType: "auto", Command: "native/windows/security_policy/Registry/ForceGuest", Collect: collectWindowsForceGuestCheck},
		{ID: "W-SMB-007", SectionType: "auto", Command: "native/windows/security_policy/Registry/RequireSecuritySignature(server)", Collect: collectWindowsServerRequireSecuritySignatureCheck},
		{ID: "W-SMB-008", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableSecuritySignature(client)", Collect: collectWindowsClientEnableSecuritySignatureCheck},
		{ID: "W-SMB-009", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnablePlainTextPassword", Collect: collectWindowsEnablePlainTextPasswordCheck},
		{ID: "W-SMB-010", SectionType: "auto", Command: "native/windows/security_policy/Registry/AutoDisconnect", Collect: collectWindowsAutoDisconnectCheck},
		{ID: "W-SMB-011", SectionType: "auto", Command: "native/windows/security_policy/Registry/EnableForcedLogOff", Collect: collectWindowsEnableForcedLogOffCheck},
		{ID: "W-NETLOGON-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/RequireSignOrSeal", Collect: collectWindowsRequireSignOrSealCheck},
		{ID: "W-NETLOGON-002", SectionType: "auto", Command: "native/windows/security_policy/Registry/RequireStrongKey", Collect: collectWindowsRequireStrongKeyCheck},
		{ID: "W-NETLOGON-003", SectionType: "auto", Command: "native/windows/security_policy/Registry/SealSecureChannel", Collect: collectWindowsSealSecureChannelCheck},
		{ID: "W-NETLOGON-004", SectionType: "auto", Command: "native/windows/security_policy/Registry/SignSecureChannel", Collect: collectWindowsSignSecureChannelCheck},
		{ID: "W-NETLOGON-005", SectionType: "auto", Command: "native/windows/security_policy/Registry/DisablePasswordChange", Collect: collectWindowsDisablePasswordChangeCheck},
		{ID: "W-NETLOGON-006", SectionType: "auto", Command: "native/windows/security_policy/Registry/MaximumPasswordAge(machine)", Collect: collectWindowsMachineMaximumPasswordAgeCheck},
		{ID: "W-LDAP-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/LDAPClientIntegrity", Collect: collectWindowsLDAPClientIntegrityCheck},
		{ID: "W-CRED-001", SectionType: "auto", Command: "native/windows/security_policy/Registry/DisableDomainCreds", Collect: collectWindowsDisableDomainCredsCheck},
		{ID: "W-PRIV-001", SectionType: "auto", Command: "native/windows/security_policy/Privilege Rights/SeDenyNetworkLogonRight", Collect: collectWindowsDenyGuestNetworkLogonCheck},
		{ID: "W-PRIV-002", SectionType: "auto", Command: "native/windows/security_policy/Privilege Rights/SeDenyInteractiveLogonRight", Collect: collectWindowsDenyGuestInteractiveLogonCheck},
		{ID: "W-ACC-005", SectionType: "auto", Command: "native/windows/security_policy/System Access/EnableAdminAccount", Collect: collectWindowsAdminAccountDisabledCheck},
		{ID: "8", SectionType: "display", Command: `wmic timezone get caption,standardname | find /i /v "standardname"`, Collect: collectWindowsTimezoneCheck},
		{ID: "4", SectionType: "display", Command: `wmic useraccount where Domain="%computername%" get caption,description,PasswordChangeable,PasswordExpires,PasswordRequired,Lockout,status`, Collect: collectWindowsAccountsCheck},
		{ID: "0", SectionType: "display", Command: `netstat -an`, Collect: collectWindowsConnectionsCheck},
		{ID: "9", SectionType: "display", Command: `wmic startup get caption,command,location`, Collect: collectWindowsStartupCommandsCheck},
		{ID: "12", SectionType: "display", Command: `wmic qfe get description,hotfixid,installedon,installedby`, Collect: collectWindowsHotfixesCheck},
		{ID: "5", SectionType: "display", Command: `wmic group where Domain="%computername%" get caption,description,status`, Collect: collectWindowsGroupsCheck},
		{ID: "6", SectionType: "display", Command: `wmic service get caption,pathname,startmode,state`, Collect: collectWindowsServicesCheck},
		{ID: "1", SectionType: "display", Command: `tasklist`, Collect: collectWindowsProcessesCheck},
		{ID: "3", SectionType: "display", Command: `hostname`, Collect: collectWindowsHostNameCheck},
		{ID: "2", SectionType: "display", Command: `wmic os get caption,csdversion,version`, Collect: collectWindowsOSCheck},
		{ID: "10", SectionType: "display", Command: `wmic share get description,name,path`, Collect: collectWindowsSharesCheck},
		{ID: "7", SectionType: "display", Command: `del /f/s/q %tmp%\\NSF{nsf_tm}_*.{log,txt,vbs,bat}`, Collect: collectWindowsCleanupCheck},
	}
}

func collectWindowsHostNameCheck(_ context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	hostName := state.hostName()
	if hostName == "" {
		hostName, _ = os.Hostname()
	}
	return benchmarkCheckResult{
		Actual:   hostName,
		Evidence: hostName,
		Eval: map[string]any{
			"hostname": hostName,
		},
	}, nil
}

func collectWindowsOSCheck(_ context.Context, _ *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	info, err := collectWindowsOSInfo()
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	evidence := mustMarshalPrettyJSON(map[string]any{
		"Caption":    info.ProductName,
		"CSDVersion": info.CSDVersion,
		"Version":    firstNonEmpty(info.DisplayVersion, info.CurrentBuildNumber),
	})
	return benchmarkCheckResult{
		Actual:   summarizeWindowsOSInfo(info),
		Evidence: evidence,
		Eval: map[string]any{
			"product_name":    info.ProductName,
			"display_version": info.DisplayVersion,
			"build_number":    info.CurrentBuildNumber,
		},
	}, nil
}

func collectWindowsTimezoneCheck(_ context.Context, _ *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	info, err := collectWindowsTimezoneInfo()
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	evidence := mustMarshalPrettyJSON(map[string]any{
		"Caption":      info.DisplayName,
		"StandardName": info.StandardName,
		"TimeZoneKey":  info.KeyName,
	})
	return benchmarkCheckResult{
		Actual:   summarizeWindowsTimezone(info),
		Evidence: evidence,
		Eval: map[string]any{
			"key_name":      info.KeyName,
			"display_name":  info.DisplayName,
			"standard_name": info.StandardName,
		},
	}, nil
}

func collectWindowsAccountsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.userAccounts == nil {
		rows, err := collectWindowsUserAccounts(ctx)
		if err != nil {
			rows = nil
		}
		if len(rows) == 0 {
			result, scanErr := accountscan.Scan(ctx, accountscan.AccountScanParams{})
			if scanErr != nil && err != nil {
				return benchmarkCheckResult{}, err
			}
			if scanErr == nil {
				rows = make([]windowsUserAccountRecord, 0, len(result.Rows))
				for i := range result.Rows {
					row := result.Rows[i]
					caption := derefString(row.Name)
					if host := derefString(row.Hostname); host != "" && caption != "" {
						caption = host + `\` + caption
					}
					rows = append(rows, windowsUserAccountRecord{
						Caption:            caption,
						Description:        derefString(row.Description),
						PasswordChangeable: row.PasswordChangeable,
						PasswordExpires:    row.PasswordExpires,
						PasswordRequired:   row.PasswordRequired,
						Lockout:            row.Lockout,
						Status:             derefString(row.StatusText),
					})
				}
			}
		}
		state.userAccounts = rows
	}
	evidence := make([]map[string]any, 0, len(state.userAccounts))
	for _, row := range state.userAccounts {
		item := map[string]any{
			"Caption":            row.Caption,
			"Description":        row.Description,
			"PasswordChangeable": derefBool(row.PasswordChangeable),
			"PasswordExpires":    derefBool(row.PasswordExpires),
			"PasswordRequired":   derefBool(row.PasswordRequired),
			"Lockout":            derefBool(row.Lockout),
			"Status":             row.Status,
		}
		evidence = append(evidence, item)
	}
	return benchmarkCheckResult{
		Actual:   summarizeNamedCount("local accounts", accountCaptions(state.userAccounts), 8),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.userAccounts),
		},
	}, nil
}

func collectWindowsGroupsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.groupDetails == nil {
		rows, err := collectWindowsLocalGroups(ctx)
		if err != nil {
			rows = nil
		}
		if len(rows) == 0 {
			result, scanErr := usergroupscan.Scan(ctx, usergroupscan.UserGroupScanParams{})
			if scanErr != nil && err != nil {
				return benchmarkCheckResult{}, err
			}
			if scanErr == nil {
				rows = make([]windowsGroupRecord, 0, len(result.Rows))
				for i := range result.Rows {
					row := result.Rows[i]
					caption := derefString(row.Name)
					if host := derefString(row.Hostname); host != "" && caption != "" {
						caption = host + `\` + caption
					}
					rows = append(rows, windowsGroupRecord{
						Caption:     caption,
						Description: derefString(row.Description),
						Status:      derefString(row.StatusText),
					})
				}
			}
		}
		state.groupDetails = rows
	}
	evidence := make([]map[string]any, 0, len(state.groupDetails))
	for _, row := range state.groupDetails {
		item := map[string]any{
			"Caption":     row.Caption,
			"Description": row.Description,
			"Status":      row.Status,
		}
		evidence = append(evidence, item)
	}
	return benchmarkCheckResult{
		Actual:   summarizeNamedCount("local groups", groupCaptions(state.groupDetails), 8),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.groupDetails),
		},
	}, nil
}

func collectWindowsServicesCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.serviceRows == nil {
		rows, err := collectWindowsServiceDetails(ctx)
		if err != nil {
			rows = nil
		}
		if len(rows) == 0 {
			result, scanErr := startupscan.Scan(ctx, startupscan.StartupScanParams{})
			if scanErr != nil && err != nil {
				return benchmarkCheckResult{}, err
			}
			if scanErr == nil {
				rows = make([]windowsServiceRecord, 0, len(result.Rows))
				for i := range result.Rows {
					row := result.Rows[i]
					rows = append(rows, windowsServiceRecord{
						Caption:   firstNonEmpty(derefString(row.ShowName), derefString(row.Name)),
						PathName:  derefString(row.ExecPath),
						StartMode: windowsStartModeText(row.StartType),
						State:     windowsFallbackServiceState(row.Enable),
					})
				}
			}
		}
		state.serviceRows = rows
	}
	evidence := make([]map[string]any, 0, len(state.serviceRows))
	for _, row := range state.serviceRows {
		item := map[string]any{
			"Caption":   row.Caption,
			"PathName":  row.PathName,
			"StartMode": row.StartMode,
			"State":     row.State,
		}
		evidence = append(evidence, item)
	}
	return benchmarkCheckResult{
		Actual:   summarizeNamedCount("services", serviceCaptions(state.serviceRows), 8),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.serviceRows),
		},
	}, nil
}

func collectWindowsProcessesCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.process == nil {
		rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.process = make([]*processscan.ProcessInfo, 0, len(rows))
		for i := range rows {
			row := rows[i]
			state.process = append(state.process, &row)
		}
	}
	evidence := make([]map[string]any, 0, len(state.process))
	for _, row := range state.process {
		if row == nil {
			continue
		}
		evidence = append(evidence, map[string]any{
			"ImageName":   derefString(row.Name),
			"PID":         derefInt(row.PID),
			"SessionName": derefString(row.SessionName),
			"Session#":    derefInt(row.SessionID),
			"Path":        derefString(row.Path),
		})
	}
	return benchmarkCheckResult{
		Actual:   summarizeNamedCount("processes", processNames(state.process), 10),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.process),
		},
	}, nil
}

func collectWindowsStartupCommandsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.startupRows == nil {
		rows, err := collectWindowsStartupCommandDetails(ctx)
		if err != nil {
			entries, collectErr := collectWindowsStartupCommands()
			if collectErr != nil {
				return benchmarkCheckResult{}, err
			}
			state.startupCommands = entries
		} else {
			state.startupRows = rows
		}
	}
	evidence := make([]map[string]any, 0, len(state.startupRows)+len(state.startupCommands))
	for _, row := range state.startupRows {
		evidence = append(evidence, map[string]any{
			"Caption":  row.Caption,
			"Command":  row.Command,
			"Location": row.Location,
		})
	}
	for _, row := range state.startupCommands {
		evidence = append(evidence, map[string]any{
			"Caption":  row.Name,
			"Command":  row.Command,
			"Location": row.Location,
		})
	}
	count := len(state.startupRows)
	actual := summarizeStartupCommandRows(state.startupRows)
	if len(state.startupCommands) > 0 {
		count = len(state.startupCommands)
		actual = summarizeStartupCommands(state.startupCommands)
	}
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": count,
		},
	}, nil
}

func collectWindowsConnectionsCheck(_ context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.connections == nil {
		rows, err := collectWindowsNetConnections()
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.connections = rows
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsConnections(state.connections),
		Evidence: mustMarshalPrettyJSON(state.connections),
		Eval: map[string]any{
			"count": len(state.connections),
		},
	}, nil
}

func collectWindowsSharesCheck(_ context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.shares == nil {
		shares, err := collectWindowsShares()
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.shares = shares
	}
	evidence := make([]map[string]any, 0, len(state.shares))
	for _, row := range state.shares {
		evidence = append(evidence, map[string]any{
			"Description": row.Remark,
			"Name":        row.Name,
			"Path":        row.Path,
		})
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsShares(state.shares),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.shares),
		},
	}, nil
}

func collectWindowsHotfixesCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.hotfixes == nil {
		hotfixes, err := collectWindowsHotfixes(ctx)
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.hotfixes = hotfixes
	}
	evidence := make([]map[string]any, 0, len(state.hotfixes))
	for _, row := range state.hotfixes {
		evidence = append(evidence, map[string]any{
			"Description": row.Description,
			"HotFixID":    row.HotFixID,
			"InstalledOn": row.InstalledOn,
			"InstalledBy": row.InstalledBy,
		})
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsHotfixes(state.hotfixes),
		Evidence: mustMarshalPrettyJSON(evidence),
		Eval: map[string]any{
			"count": len(state.hotfixes),
		},
	}, nil
}

func collectWindowsCleanupCheck(_ context.Context, _ *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return benchmarkCheckResult{
		Actual:   "native cleanup not required",
		Evidence: "native cleanup not required",
		Eval: map[string]any{
			"cleanup_required": false,
		},
	}, nil
}

func collectWindowsFirewallCheck(_ context.Context, _ *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	info, err := collectWindowsFirewallInfo()
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsFirewall(info),
		Evidence: mustMarshalPrettyJSON(info),
		Eval: map[string]any{
			"enabled": info.Enabled,
		},
	}, nil
}

func collectWindowsFilesystemCheck(_ context.Context, _ *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	info, err := collectWindowsFilesystemInfo()
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsFilesystem(info),
		Evidence: mustMarshalPrettyJSON(info),
		Eval: map[string]any{
			"all_ntfs": info.AllNTFS,
		},
	}, nil
}

func collectWindowsAntivirusCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.services == nil {
		result, err := startupscan.Scan(ctx, startupscan.StartupScanParams{})
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.services = make([]*startupscan.StartupInfo, 0, len(result.Rows))
		for i := range result.Rows {
			row := result.Rows[i]
			state.services = append(state.services, &row)
		}
	}
	if state.process == nil {
		rows, err := processscan.Scan(ctx, processscan.ProcessScanParams{})
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.process = make([]*processscan.ProcessInfo, 0, len(rows))
		for i := range rows {
			row := rows[i]
			state.process = append(state.process, &row)
		}
	}

	info, err := collectWindowsAntivirusInfo(ctx, state.services, state.process)
	if err != nil {
		return benchmarkCheckResult{}, err
	}
	return benchmarkCheckResult{
		Actual:   summarizeWindowsAntivirus(info),
		Evidence: mustMarshalPrettyJSON(info),
		Eval: map[string]any{
			"detected": info.Detected,
		},
	}, nil
}

func collectWindowsEveryoneShareCheck(_ context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	if state.shares == nil {
		shares, err := collectWindowsShares()
		if err != nil {
			return benchmarkCheckResult{}, err
		}
		state.shares = shares
	}

	everyoneAbsent := true
	var offenders []string
	for _, share := range state.shares {
		if share.EveryonePresent {
			everyoneAbsent = false
			offenders = append(offenders, share.Name)
		}
	}

	actual := "no Everyone share permissions detected"
	if !everyoneAbsent {
		actual = fmt.Sprintf("Everyone present on shares: %s", strings.Join(offenders, ", "))
	}
	return benchmarkCheckResult{
		Actual:   actual,
		Evidence: mustMarshalPrettyJSON(state.shares),
		Eval: map[string]any{
			"everyone_absent": everyoneAbsent,
		},
	}, nil
}

func collectWindowsMinimumPasswordLengthCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "MinimumPasswordLength", "system_access", "MinimumPasswordLength")
}

func collectWindowsPasswordComplexityCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "PasswordComplexity", "system_access", "PasswordComplexity")
}

func collectWindowsPasswordHistoryCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "PasswordHistorySize", "system_access", "PasswordHistorySize")
}

func collectWindowsMaximumPasswordAgeCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "MaximumPasswordAge", "system_access", "MaximumPasswordAge")
}

func collectWindowsMinimumPasswordAgeCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "MinimumPasswordAge", "system_access", "MinimumPasswordAge")
}

func collectWindowsLockoutBadCountCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "LockoutBadCount", "system_access", "LockoutBadCount")
}

func collectWindowsAllowAdministratorLockoutCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AllowAdministratorLockout", "system_access", "AllowAdministratorLockout")
}

func collectWindowsResetLockoutCountCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ResetLockoutCount", "system_access", "ResetLockoutCount")
}

func collectWindowsLockoutDurationCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "LockoutDuration", "system_access", "LockoutDuration")
}

func collectWindowsGuestAccountDisabledCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableGuestAccount", "system_access", "EnableGuestAccount")
}

func collectWindowsAdministratorRenameCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "NewAdministratorName", "system_access", "NewAdministratorName")
}

func collectWindowsGuestRenameCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "NewGuestName", "system_access", "NewGuestName")
}

func collectWindowsBlankPasswordRestrictionCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "LimitBlankPasswordUse", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse`)
}

func collectWindowsClearTextPasswordCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ClearTextPassword", "system_access", "ClearTextPassword")
}

func collectWindowsAuditLogonEventsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AuditLogonEvents", "event_audit", "AuditLogonEvents")
}

func collectWindowsAuditAccountLogonCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AuditAccountLogon", "event_audit", "AuditAccountLogon")
}

func collectWindowsAuditSystemEventsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AuditSystemEvents", "event_audit", "AuditSystemEvents")
}

func collectWindowsAuditPolicyChangeCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AuditPolicyChange", "event_audit", "AuditPolicyChange")
}

func collectWindowsAuditAccountManageCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AuditAccountManage", "event_audit", "AuditAccountManage")
}

func collectWindowsEnableLUACheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableLUA", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`)
}

func collectWindowsFilterAdministratorTokenCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "FilterAdministratorToken", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`)
}

func collectWindowsPromptOnSecureDesktopCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "PromptOnSecureDesktop", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`)
}

func collectWindowsEnableInstallerDetectionCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableInstallerDetection", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`)
}

func collectWindowsEnableSecureUIAPathsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableSecureUIAPaths", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`)
}

func collectWindowsEnableVirtualizationCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableVirtualization", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`)
}

func collectWindowsConsentPromptBehaviorAdminCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ConsentPromptBehaviorAdmin", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin`)
}

func collectWindowsConsentPromptBehaviorUserCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ConsentPromptBehaviorUser", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`)
}

func collectWindowsDontDisplayLastUserNameCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "DontDisplayLastUserName", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName`)
}

func collectWindowsShutdownWithoutLogonCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ShutdownWithoutLogon", "registry", `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon`)
}

func collectWindowsCachedLogonsCountCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "CachedLogonsCount", "registry", `MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount`)
}

func collectWindowsRestrictNullSessionCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "RestrictNullSessAccess", "registry", `MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess`)
}

func collectWindowsNoLMHashCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "NoLMHash", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash`)
}

func collectWindowsRestrictAnonymousSAMCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "RestrictAnonymousSAM", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM`)
}

func collectWindowsEveryoneIncludesAnonymousCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EveryoneIncludesAnonymous", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous`)
}

func collectWindowsLSAAnonymousNameLookupCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "LSAAnonymousNameLookup", "system_access", "LSAAnonymousNameLookup")
}

func collectWindowsForceGuestCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "ForceGuest", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest`)
}

func collectWindowsServerRequireSecuritySignatureCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "RequireSecuritySignature", "registry", `MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature`)
}

func collectWindowsClientEnableSecuritySignatureCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableSecuritySignature", "registry", `MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature`)
}

func collectWindowsEnablePlainTextPasswordCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnablePlainTextPassword", "registry", `MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword`)
}

func collectWindowsAutoDisconnectCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "AutoDisconnect", "registry", `MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect`)
}

func collectWindowsEnableForcedLogOffCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableForcedLogOff", "registry", `MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff`)
}

func collectWindowsRequireSignOrSealCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "RequireSignOrSeal", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal`)
}

func collectWindowsRequireStrongKeyCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "RequireStrongKey", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey`)
}

func collectWindowsSealSecureChannelCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "SealSecureChannel", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel`)
}

func collectWindowsSignSecureChannelCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "SignSecureChannel", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel`)
}

func collectWindowsDisablePasswordChangeCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "DisablePasswordChange", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange`)
}

func collectWindowsMachineMaximumPasswordAgeCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "MaximumPasswordAge", "registry", `MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge`)
}

func collectWindowsLDAPClientIntegrityCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "LDAPClientIntegrity", "registry", `MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity`)
}

func collectWindowsDisableDomainCredsCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "DisableDomainCreds", "registry", `MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds`)
}

func collectWindowsDenyGuestNetworkLogonCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPrivilegeMembershipCheck(ctx, state, "SeDenyNetworkLogonRight", "Guest")
}

func collectWindowsDenyGuestInteractiveLogonCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPrivilegeMembershipCheck(ctx, state, "SeDenyInteractiveLogonRight", "Guest")
}

func collectWindowsAdminAccountDisabledCheck(ctx context.Context, state *windowsBenchmarkCollectorState) (benchmarkCheckResult, error) {
	return collectWindowsPolicyCheck(ctx, state, "EnableAdminAccount", "system_access", "EnableAdminAccount")
}

func writeWindowsBenchmarkTraceXML(workingRoot string, state *windowsBenchmarkCollectorState, checks []benchmarkCheckResult) (string, error) {
	profile := nativeWindowsProfile()
	sections := map[string][]xmlItem{
		"auto":    {},
		"display": {},
	}

	for _, check := range checks {
		section := firstNonEmpty(check.SectionType, "display")
		item := xmlItem{
			Flag: check.ID,
			Cmd: xmlCmd{
				Info:    time.Now().Format("2006-1-2"),
				Command: check.Command,
				Value:   check.Evidence,
			},
		}
		sections[section] = append(sections[section], item)
	}

	raw := baselineXML{
		UUID: profile.uuid,
		IP:   state.hostIP(),
		Time: profile.templateTime,
		Security: []xmlSection{
			{Type: "auto", Items: sections["auto"]},
			{Type: "display", Items: sections["display"]},
		},
	}

	payload, err := xml.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal windows benchmark trace xml failed: %w", err)
	}

	hostPart := sanitizeFileComponent(raw.IP)
	if hostPart == "" {
		hostPart = "unknown-host"
	}
	fileName := fmt.Sprintf("%s_%s_chk.xml", hostPart, profile.uuid)
	outPath := filepath.Join(workingRoot, fileName)
	data := append([]byte(xml.Header), payload...)
	data = append(data, []byte(windowsTemplateExtraComment())...)
	data = append(data, '\n')
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write windows benchmark trace xml failed: %w", err)
	}
	return outPath, nil
}

func collectWindowsOSInfo() (windowsOSInfo, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return windowsOSInfo{}, err
	}
	defer key.Close()

	info := windowsOSInfo{}
	info.ProductName, _, _ = key.GetStringValue("ProductName")
	info.DisplayVersion, _, _ = key.GetStringValue("DisplayVersion")
	info.ReleaseID, _, _ = key.GetStringValue("ReleaseId")
	info.CurrentVersion, _, _ = key.GetStringValue("CurrentVersion")
	info.CurrentBuildNumber, _, _ = key.GetStringValue("CurrentBuildNumber")
	info.CSDVersion, _, _ = key.GetStringValue("CSDVersion")
	if ubr, _, err := key.GetIntegerValue("UBR"); err == nil {
		info.UBR = ubr
	}
	return info, nil
}

func collectWindowsTimezoneInfo() (windowsTimezoneInfo, error) {
	var info windowsTimezoneInfo
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, registry.QUERY_VALUE)
	if err != nil {
		return info, err
	}
	defer key.Close()

	info.KeyName, _, _ = key.GetStringValue("TimeZoneKeyName")
	info.StandardName, _, _ = key.GetStringValue("StandardName")
	info.DaylightName, _, _ = key.GetStringValue("DaylightName")
	if bias, _, err := key.GetIntegerValue("Bias"); err == nil {
		info.BiasMinutes = int32(bias)
	}

	if info.KeyName != "" {
		tzKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\`+info.KeyName, registry.QUERY_VALUE)
		if err == nil {
			info.DisplayName, _, _ = tzKey.GetStringValue("Display")
			if info.StandardName == "" {
				info.StandardName, _, _ = tzKey.GetStringValue("Std")
			}
			if info.DaylightName == "" {
				info.DaylightName, _, _ = tzKey.GetStringValue("Dlt")
			}
			_ = tzKey.Close()
		}
	}
	return info, nil
}

func collectWindowsStartupCommands() ([]windowsStartupCommandEntry, error) {
	type runKey struct {
		root     registry.Key
		path     string
		location string
	}

	keys := []runKey{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	}

	var out []windowsStartupCommandEntry
	for _, item := range keys {
		key, err := registry.OpenKey(item.root, item.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := key.ReadValueNames(0)
		if err != nil {
			key.Close()
			continue
		}
		for _, name := range names {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			out = append(out, windowsStartupCommandEntry{
				Name:     strings.TrimSpace(name),
				Command:  strings.TrimSpace(value),
				Location: item.location,
			})
		}
		key.Close()
	}

	for _, root := range windowsStartupFolders() {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			fullPath := filepath.Join(root, entry.Name())
			out = append(out, windowsStartupCommandEntry{
				Name:     entry.Name(),
				Command:  fullPath,
				Location: root,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if !strings.EqualFold(out[i].Location, out[j].Location) {
			return strings.ToLower(out[i].Location) < strings.ToLower(out[j].Location)
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func windowsStartupFolders() []string {
	var roots []string
	if appData := os.Getenv("APPDATA"); appData != "" {
		roots = append(roots, filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	}
	if programData := os.Getenv("ProgramData"); programData != "" {
		roots = append(roots, filepath.Join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"))
	}
	return roots
}

func collectWindowsHotfixesFromRegistry() ([]windowsHotfixInfo, error) {
	keys := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}

	seen := map[string]windowsHotfixInfo{}
	for _, item := range keys {
		key, err := registry.OpenKey(item.root, item.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}
		for _, name := range names {
			kbID := extractKBID(name)
			if kbID == "" {
				sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
				if err != nil {
					continue
				}
				displayName, _, _ := sub.GetStringValue("DisplayName")
				hotfixID, _, _ := sub.GetStringValue("HotFixID")
				kbID = firstNonEmpty(strings.TrimSpace(hotfixID), extractKBID(displayName))
				if kbID == "" {
					sub.Close()
					continue
				}
				info := seen[kbID]
				info.HotFixID = kbID
				info.Source = firstNonEmpty(info.Source, item.path)
				info.Description = firstNonEmpty(info.Description, strings.TrimSpace(displayName))
				sub.Close()
				seen[kbID] = info
				continue
			}

			sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
			if err != nil {
				info := seen[kbID]
				info.HotFixID = kbID
				info.Source = firstNonEmpty(info.Source, item.path)
				seen[kbID] = info
				continue
			}
			info := seen[kbID]
			info.HotFixID = kbID
			info.Source = firstNonEmpty(info.Source, item.path)
			if state, _, err := sub.GetIntegerValue("CurrentState"); err == nil {
				info.PackageState = state
			}
			if installName, _, err := sub.GetStringValue("InstallName"); err == nil {
				info.Description = firstNonEmpty(info.Description, strings.TrimSpace(installName))
			}
			if installedBy, _, err := sub.GetStringValue("InstalledBy"); err == nil {
				info.InstalledBy = firstNonEmpty(info.InstalledBy, strings.TrimSpace(installedBy))
			}
			if installDate, _, err := sub.GetStringValue("InstallDate"); err == nil {
				info.InstalledOn = firstNonEmpty(info.InstalledOn, strings.TrimSpace(installDate))
			}
			sub.Close()
			seen[kbID] = info
		}
		key.Close()
	}

	out := make([]windowsHotfixInfo, 0, len(seen))
	for _, info := range seen {
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		return hotfixNumericKey(out[i].HotFixID) > hotfixNumericKey(out[j].HotFixID)
	})
	return out, nil
}

func collectWindowsFirewallInfo() (windowsFirewallInfo, error) {
	profiles := []string{"DomainProfile", "StandardProfile", "PublicProfile"}
	info := windowsFirewallInfo{Profiles: make([]windowsFirewallProfile, 0, len(profiles))}
	allEnabled := true

	for _, profile := range profiles {
		path := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + profile
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			allEnabled = false
			info.Profiles = append(info.Profiles, windowsFirewallProfile{Name: profile, Enabled: false})
			continue
		}
		enabled := false
		if value, _, err := key.GetIntegerValue("EnableFirewall"); err == nil {
			enabled = value != 0
		}
		key.Close()
		if !enabled {
			allEnabled = false
		}
		info.Profiles = append(info.Profiles, windowsFirewallProfile{Name: profile, Enabled: enabled})
	}

	info.Enabled = allEnabled
	return info, nil
}

func collectWindowsFilesystemInfo() (windowsFilesystemInfo, error) {
	drives, err := listWindowsFixedDrives()
	if err != nil {
		return windowsFilesystemInfo{}, err
	}
	allNTFS := true
	for _, drive := range drives {
		if !strings.EqualFold(strings.TrimSpace(drive.FileSystem), "NTFS") {
			allNTFS = false
			break
		}
	}
	return windowsFilesystemInfo{
		AllNTFS: allNTFS,
		Drives:  drives,
	}, nil
}

func collectWindowsAntivirusInfo(ctx context.Context, services []*startupscan.StartupInfo, processes []*processscan.ProcessInfo) (windowsAntivirusInfo, error) {
	securityCenterProducts, err := collectWindowsSecurityCenterProductNames(ctx)
	if err != nil {
		return windowsAntivirusInfo{}, err
	}
	productHints, err := collectWindowsAntivirusProductHints()
	if err != nil {
		return windowsAntivirusInfo{}, err
	}

	serviceIndicators := collectWindowsAntivirusServiceIndicators(services)
	processIndicators := collectWindowsAntivirusProcessIndicators(processes)
	detected := len(securityCenterProducts) > 0 || len(productHints) > 0 || len(serviceIndicators) > 0 || len(processIndicators) > 0
	return windowsAntivirusInfo{
		Detected:               detected,
		SecurityCenterProducts: securityCenterProducts,
		ProductHints:           productHints,
		ServiceIndicators:      serviceIndicators,
		ProcessIndicators:      processIndicators,
	}, nil
}

func profileUUIDForTemplate(template Template) string {
	profile, err := nativeProfileForTemplate(template)
	if err != nil {
		return ""
	}
	return profile.uuid
}

func profileTimeForTemplate(template Template) string {
	profile, err := nativeProfileForTemplate(template)
	if err != nil {
		return ""
	}
	return profile.templateTime
}

func windowsTemplateExtraComment() string {
	return "<!--\n" +
		"    <extra>\n" +
		fmt.Sprintf("        <product>%s</product>\n", windowsTemplateInfo.Product) +
		fmt.Sprintf("        <template>%s</template>\n", windowsTemplateInfo.TemplateName) +
		fmt.Sprintf("        <templatever>%s</templatever>\n", windowsTemplateInfo.TemplateVersion) +
		fmt.Sprintf("        <industry>%s</industry>\n", windowsTemplateInfo.Industry) +
		fmt.Sprintf("        <version>%s</version>\n", windowsTemplateInfo.SystemVersion) +
		fmt.Sprintf("        <hash>%s</hash>\n", windowsTemplateInfo.Hash) +
		"    </extra>\n" +
		"-->\n"
}

func collectWindowsAntivirusProductHints() ([]string, error) {
	keyPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	seen := map[string]struct{}{}
	var out []string
	for _, path := range keyPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		names, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}
		for _, name := range names {
			sub, err := registry.OpenKey(key, name, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			displayName, _, _ := sub.GetStringValue("DisplayName")
			parentName, _, _ := sub.GetStringValue("ParentDisplayName")
			parentKey, _, _ := sub.GetStringValue("ParentKeyName")
			systemComponent, _, _ := sub.GetIntegerValue("SystemComponent")
			sub.Close()
			if systemComponent != 0 {
				continue
			}
			if strings.TrimSpace(parentName) != "" || strings.TrimSpace(parentKey) != "" {
				continue
			}
			displayName = strings.TrimSpace(displayName)
			if displayName == "" {
				continue
			}
			if !containsWindowsAntivirusKeyword(displayName) {
				continue
			}
			if _, ok := seen[displayName]; ok {
				continue
			}
			seen[displayName] = struct{}{}
			out = append(out, displayName)
		}
		key.Close()
	}
	sort.Strings(out)
	return out, nil
}

func collectWindowsAntivirusServiceIndicators(services []*startupscan.StartupInfo) []string {
	if len(services) == 0 {
		return nil
	}
	known := map[string]struct{}{}
	for _, name := range windowsAntivirusServiceNames {
		known[strings.ToLower(name)] = struct{}{}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, service := range services {
		if service == nil || service.Name == nil {
			continue
		}
		name := strings.TrimSpace(*service.Name)
		if name == "" {
			continue
		}
		if _, ok := known[strings.ToLower(name)]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func collectWindowsAntivirusProcessIndicators(processes []*processscan.ProcessInfo) []string {
	known := map[string]struct{}{}
	for _, name := range windowsAntivirusProcessNames {
		known[strings.ToLower(name)] = struct{}{}
	}

	seen := map[string]struct{}{}
	var out []string
	for _, process := range processes {
		if process == nil || process.Name == nil {
			continue
		}
		name := strings.TrimSpace(*process.Name)
		if name == "" {
			continue
		}
		if _, ok := known[strings.ToLower(name)]; !ok {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

var windowsAntivirusKeywords = []string{
	"安全部队",
	"杀毒",
	"反病毒",
	"防病毒",
	"virus",
	"spyware",
	"symantec endpoint protection",
	"windows defender",
	"microsoft defender",
}

var windowsAntivirusServiceNames = []string{
	"WinDefend", "WdNisSvc", "SecurityHealthService", "BEService", "wpscloudsvr",
}

var windowsAntivirusProcessNames = []string{
	"kvwsc.exe", "kvmonxp.exe", "ashserv.exe", "aswupdsv.exe", "ashdisp.exe", "ashwebsv.exe",
	"updaterui.exe", "shstat.exe", "tbmon.exe", "ccproxy.exe", "ntrtscan.exe", "ccsetmgr.exe",
	"defwatch.exe", "issvc.exe", "spbbcsvc.exe", "sndsrvc.exe", "kpfwsvc.exe", "kavstart.exe",
	"kwatch.exe", "kmailmon.exe", "kpfw32.exe", "kavscr.exe", "avp.exe", "kvsrvxp.exe",
	"vstskmgr.exe", "mcshield.exe", "frameworkservice.exe", "naprdmgr.exe", "mcafee.exe",
	"xcommsvr.exe", "bdss.exe", "livesrv.exe", "bdmcon.exe", "bdoesrv.exe", "bdnagent.exe",
	"spidernt.exe", "spiderml.exe", "drwebscd.exe", "spider.exe", "nod32kui.exe", "nod32krn.exe",
	"mpsvc.exe", "mpsvc1.exe", "mpsvc2.exe", "ravmond.exe", "rfwmain.exe", "msseces.exe",
	"360tray.exe", "zhudongfangyu.exe", "ds_agent", "ds_notifier", "msmpeng.exe", "securityhealthservice.exe",
}

func containsWindowsAntivirusKeyword(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, keyword := range windowsAntivirusKeywords {
		if strings.Contains(normalized, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func extractKBID(value string) string {
	upper := strings.ToUpper(strings.TrimSpace(value))
	idx := strings.Index(upper, "KB")
	if idx < 0 {
		return ""
	}
	upper = upper[idx:]
	end := 2
	for end < len(upper) && upper[end] >= '0' && upper[end] <= '9' {
		end++
	}
	if end <= 2 {
		return ""
	}
	return upper[:end]
}

func hotfixNumericKey(value string) string {
	return strings.TrimLeft(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "KB"), "0")
}

func summarizeWindowsOSInfo(info windowsOSInfo) string {
	parts := []string{strings.TrimSpace(info.ProductName)}
	versionPart := strings.TrimSpace(info.DisplayVersion)
	if versionPart == "" {
		versionPart = strings.TrimSpace(info.ReleaseID)
	}
	if versionPart != "" {
		parts = append(parts, versionPart)
	}
	build := strings.TrimSpace(info.CurrentBuildNumber)
	if build != "" {
		if info.UBR > 0 {
			parts = append(parts, fmt.Sprintf("build %s.%d", build, info.UBR))
		} else {
			parts = append(parts, "build "+build)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func summarizeWindowsTimezone(info windowsTimezoneInfo) string {
	return firstNonEmpty(
		strings.TrimSpace(info.DisplayName)+" ("+strings.TrimSpace(info.KeyName)+")",
		strings.TrimSpace(info.KeyName),
		strings.TrimSpace(info.StandardName),
	)
}

func summarizeNamedCount(label string, names []string, limit int) string {
	if len(names) == 0 {
		return "0 " + label
	}
	if limit <= 0 || len(names) <= limit {
		return fmt.Sprintf("%d %s: %s", len(names), label, strings.Join(names, ", "))
	}
	return fmt.Sprintf("%d %s: %s ...", len(names), label, strings.Join(names[:limit], ", "))
}

func summarizeStartupCommands(entries []windowsStartupCommandEntry) string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	return summarizeNamedCount("startup entries", names, 8)
}

func summarizeStartupCommandRows(entries []windowsStartupCommandRecord) string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.Caption) != "" {
			names = append(names, strings.TrimSpace(entry.Caption))
		}
	}
	sort.Strings(names)
	return summarizeNamedCount("startup entries", names, 8)
}

func summarizeWindowsConnections(rows []windowsNetConnection) string {
	tcpCount := 0
	udpCount := 0
	for _, row := range rows {
		if strings.HasPrefix(strings.ToLower(row.Protocol), "tcp") {
			tcpCount++
		} else if strings.HasPrefix(strings.ToLower(row.Protocol), "udp") {
			udpCount++
		}
	}
	return fmt.Sprintf("%d connections (%d TCP, %d UDP)", len(rows), tcpCount, udpCount)
}

func summarizeWindowsShares(shares []windowsShareInfo) string {
	names := make([]string, 0, len(shares))
	for _, share := range shares {
		names = append(names, share.Name)
	}
	sort.Strings(names)
	return summarizeNamedCount("shares", names, 8)
}

func summarizeWindowsHotfixes(items []windowsHotfixInfo) string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item.HotFixID != "" {
			ids = append(ids, item.HotFixID)
		}
	}
	return summarizeNamedCount("hotfixes", ids, 8)
}

func summarizeWindowsFirewall(info windowsFirewallInfo) string {
	var states []string
	for _, profile := range info.Profiles {
		state := "disabled"
		if profile.Enabled {
			state = "enabled"
		}
		states = append(states, profile.Name+"="+state)
	}
	return strings.Join(states, ", ")
}

func summarizeWindowsFilesystem(info windowsFilesystemInfo) string {
	if info.AllNTFS {
		return "All fixed drives use NTFS"
	}
	var nonNTFS []string
	for _, drive := range info.Drives {
		if !strings.EqualFold(strings.TrimSpace(drive.FileSystem), "NTFS") {
			nonNTFS = append(nonNTFS, drive.Name+"="+drive.FileSystem)
		}
	}
	if len(nonNTFS) == 0 {
		return "No fixed drives detected"
	}
	return "Non-NTFS fixed drives: " + strings.Join(nonNTFS, ", ")
}

func summarizeWindowsAntivirus(info windowsAntivirusInfo) string {
	if info.Detected {
		merged := append([]string{}, info.SecurityCenterProducts...)
		merged = append(merged, info.ProductHints...)
		merged = append(merged, info.ServiceIndicators...)
		merged = append(merged, info.ProcessIndicators...)
		return summarizeNamedCount("antivirus indicators", merged, 8)
	}
	return "No antivirus indicator detected"
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func derefBool(value *bool) bool {
	if value == nil {
		return false
	}
	return *value
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func windowsStartModeText(value *int) string {
	if value == nil {
		return ""
	}
	switch *value {
	case 0:
		return "Boot"
	case 1:
		return "System"
	case 2:
		return "Automatic"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return strconv.Itoa(*value)
	}
}

func windowsFallbackServiceState(enabled *bool) string {
	if enabled == nil {
		return ""
	}
	if *enabled {
		return "Running"
	}
	return "Stopped"
}

var windowsTemplateInfo = windowsTemplateMetadata{
	Product:         "BVS",
	TemplateName:    "Windows 閰嶇疆瑙勮寖_S1A1G1",
	TemplateVersion: "V6.0R03F02.0007",
	Industry:        "绛夌骇淇濇姢2.0",
	SystemVersion:   "V6.0R03F03SP07",
	Hash:            "42F1-91D7-00CD-EE46",
}

func accountCaptions(rows []windowsUserAccountRecord) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.Caption) != "" {
			out = append(out, strings.TrimSpace(row.Caption))
		}
	}
	sort.Strings(out)
	return out
}

func groupCaptions(rows []windowsGroupRecord) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.Caption) != "" {
			out = append(out, strings.TrimSpace(row.Caption))
		}
	}
	sort.Strings(out)
	return out
}

func serviceCaptions(rows []windowsServiceRecord) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if strings.TrimSpace(row.Caption) != "" {
			out = append(out, strings.TrimSpace(row.Caption))
		}
	}
	sort.Strings(out)
	return out
}

func processNames(rows []*processscan.ProcessInfo) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row != nil && row.Name != nil && strings.TrimSpace(*row.Name) != "" {
			out = append(out, strings.TrimSpace(*row.Name))
		}
	}
	sort.Strings(out)
	return out
}

func parseUint32FromString(value string) uint32 {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0
	}
	n, _ := strconv.ParseUint(trimmed, 10, 32)
	return uint32(n)
}
