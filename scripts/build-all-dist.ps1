param(
    [bool]$Offline = $true,
    [ValidateSet("static", "dynamic")]
    [string]$WindowsLinkMode = "static"
)

$ErrorActionPreference = "Stop"

function Convert-ToWslPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WindowsPath
    )

    $resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    if ($resolved -match "^([A-Za-z]):\\(.*)$") {
        $drive = $matches[1].ToLowerInvariant()
        $rest = $matches[2] -replace "\\", "/"
        return "/mnt/$drive/$rest"
    }
    throw "Cannot convert path to WSL format: $resolved"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$rootWsl = Convert-ToWslPath -WindowsPath $root
$offlineFlag = if ($Offline) { "1" } else { "0" }

Write-Host "Build all dist packages (offline=$Offline, windowsLinkMode=$WindowsLinkMode)"

Push-Location $root
try {
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64-public" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false

    bash -lc "set -euo pipefail; cd '$rootWsl'; OFFLINE=$offlineFlag COPY_RULES=0 bash ./scripts/build-linux.sh dist-linux-amd64"
    bash -lc "set -euo pipefail; cd '$rootWsl'; OFFLINE=$offlineFlag COPY_RULES=0 bash ./scripts/build-linux.sh dist-linux-amd64-public"
}
finally {
    Pop-Location
}

Write-Host "All dist directories updated."
