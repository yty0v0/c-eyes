//go:build windows

package benchmark

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

type windowsUserAccountRecord struct {
	Caption            string `json:"Caption"`
	Description        string `json:"Description,omitempty"`
	PasswordChangeable *bool  `json:"PasswordChangeable,omitempty"`
	PasswordExpires    *bool  `json:"PasswordExpires,omitempty"`
	PasswordRequired   *bool  `json:"PasswordRequired,omitempty"`
	Lockout            *bool  `json:"Lockout,omitempty"`
	Status             string `json:"Status,omitempty"`
}

type windowsGroupRecord struct {
	Caption     string `json:"Caption"`
	Description string `json:"Description,omitempty"`
	Status      string `json:"Status,omitempty"`
}

type windowsServiceRecord struct {
	Caption   string `json:"Caption"`
	PathName  string `json:"PathName,omitempty"`
	StartMode string `json:"StartMode,omitempty"`
	State     string `json:"State,omitempty"`
}

type windowsStartupCommandRecord struct {
	Caption  string `json:"Caption"`
	Command  string `json:"Command,omitempty"`
	Location string `json:"Location,omitempty"`
}

type windowsSecurityCenterProduct struct {
	Namespace   string `json:"Namespace"`
	DisplayName string `json:"DisplayName"`
}

var windowsPowerShellCommand = exec.CommandContext

func collectWindowsUserAccounts(ctx context.Context) ([]windowsUserAccountRecord, error) {
	return runWindowsPowerShellArray[windowsUserAccountRecord](ctx, `
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $source = Get-CimInstance -ClassName Win32_UserAccount -Filter "Domain='$env:COMPUTERNAME'"
} elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
    $source = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$env:COMPUTERNAME'"
} else {
    $source = @()
}
$items = $source |
    Select-Object Caption, Description, PasswordChangeable, PasswordExpires, PasswordRequired, Lockout, Status
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object Caption | ConvertTo-Json -Compress -Depth 4 }
`)
}

func collectWindowsLocalGroups(ctx context.Context) ([]windowsGroupRecord, error) {
	return runWindowsPowerShellArray[windowsGroupRecord](ctx, `
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $source = Get-CimInstance -ClassName Win32_Group -Filter "Domain='$env:COMPUTERNAME'"
} elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
    $source = Get-WmiObject -Class Win32_Group -Filter "Domain='$env:COMPUTERNAME'"
} else {
    $source = @()
}
$items = $source |
    Select-Object Caption, Description, Status
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object Caption | ConvertTo-Json -Compress -Depth 4 }
`)
}

func collectWindowsServiceDetails(ctx context.Context) ([]windowsServiceRecord, error) {
	return runWindowsPowerShellArray[windowsServiceRecord](ctx, `
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $source = Get-CimInstance -ClassName Win32_Service
} elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
    $source = Get-WmiObject -Class Win32_Service
} else {
    $source = @()
}
$items = $source |
    Select-Object Caption, PathName, StartMode, State
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object Caption | ConvertTo-Json -Compress -Depth 4 }
`)
}

func collectWindowsStartupCommandDetails(ctx context.Context) ([]windowsStartupCommandRecord, error) {
	return runWindowsPowerShellArray[windowsStartupCommandRecord](ctx, `
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $source = Get-CimInstance -ClassName Win32_StartupCommand
} elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
    $source = Get-WmiObject -Class Win32_StartupCommand
} else {
    $source = @()
}
$items = $source |
    Select-Object Caption, Command, Location
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object Caption, Location | ConvertTo-Json -Compress -Depth 4 }
`)
}

func collectWindowsSecurityCenterProductNames(ctx context.Context) ([]string, error) {
	products, err := runWindowsPowerShellArray[windowsSecurityCenterProduct](ctx, `
function Get-NativeSecurityCenterProducts {
    param([string]$Namespace)
    try {
        if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
            $source = Get-CimInstance -Namespace $Namespace -ClassName AntiVirusProduct -ErrorAction Stop
        } elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
            $source = Get-WmiObject -Namespace $Namespace -Class AntiVirusProduct -ErrorAction Stop
        } else {
            $source = @()
        }
        $source |
            Where-Object { $_.DisplayName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Namespace   = $Namespace
                    DisplayName = [string]$_.DisplayName
                }
            }
    } catch {
        @()
    }
}

$items = @()
$items += Get-NativeSecurityCenterProducts -Namespace 'root/SecurityCenter2'
if (@($items).Count -eq 0) {
    $items += Get-NativeSecurityCenterProducts -Namespace 'root/SecurityCenter'
}
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object DisplayName -Unique | ConvertTo-Json -Compress -Depth 4 }
`)
	if err != nil {
		return nil, nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(products))
	for _, product := range products {
		name := strings.TrimSpace(product.DisplayName)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func collectWindowsHotfixes(ctx context.Context) ([]windowsHotfixInfo, error) {
	type windowsQuickFixRecord struct {
		Description string `json:"Description,omitempty"`
		HotFixID    string `json:"HotFixID,omitempty"`
		InstalledOn string `json:"InstalledOn,omitempty"`
		InstalledBy string `json:"InstalledBy,omitempty"`
	}

	rows, err := runWindowsPowerShellArray[windowsQuickFixRecord](ctx, `
if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    $source = Get-CimInstance -ClassName Win32_QuickFixEngineering
} elseif (Get-Command Get-WmiObject -ErrorAction SilentlyContinue) {
    $source = Get-WmiObject -Class Win32_QuickFixEngineering
} else {
    $source = @()
}
$items = $source |
    Select-Object Description, HotFixID, @{Name='InstalledOn';Expression={ if ($_.InstalledOn) { [string]$_.InstalledOn } else { '' } }}, InstalledBy
if (@($items).Count -eq 0) { '[]' } else { @($items) | Sort-Object HotFixID -Descending | ConvertTo-Json -Compress -Depth 4 }
`)
	if err != nil {
		legacy, legacyErr := collectWindowsHotfixesFromRegistry()
		if legacyErr == nil {
			return legacy, nil
		}
		return nil, err
	}
	if len(rows) == 0 {
		legacy, legacyErr := collectWindowsHotfixesFromRegistry()
		if legacyErr == nil && len(legacy) > 0 {
			return legacy, nil
		}
	}

	out := make([]windowsHotfixInfo, 0, len(rows))
	for _, row := range rows {
		hotfixID := strings.TrimSpace(row.HotFixID)
		if hotfixID == "" {
			hotfixID = extractKBID(row.Description)
		}
		out = append(out, windowsHotfixInfo{
			HotFixID:    hotfixID,
			Source:      "Win32_QuickFixEngineering",
			InstalledOn: strings.TrimSpace(row.InstalledOn),
			InstalledBy: strings.TrimSpace(row.InstalledBy),
			Description: strings.TrimSpace(row.Description),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return hotfixNumericKey(out[i].HotFixID) > hotfixNumericKey(out[j].HotFixID)
	})
	return out, nil
}

func runWindowsPowerShellArray[T any](ctx context.Context, script string) ([]T, error) {
	output, err := runWindowsPowerShell(ctx, script)
	if err != nil {
		return nil, err
	}
	return decodeWindowsJSONArray[T](output)
}

func runWindowsPowerShell(ctx context.Context, script string) ([]byte, error) {
	wrapped := "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + script
	cmd := windowsPowerShellCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", wrapped)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell collector failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return bytes.TrimSpace(bytes.TrimPrefix(output, []byte{0xEF, 0xBB, 0xBF})), nil
}

func decodeWindowsJSONArray[T any](payload []byte) ([]T, error) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	var list []T
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}

	var single T
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return []T{single}, nil
}
