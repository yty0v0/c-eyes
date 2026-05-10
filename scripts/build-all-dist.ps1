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

function Test-WSLAvailable {
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) {
        return $false
    }
    try {
        $distros = & $wsl.Source -l -q 2>$null
        return [bool]($distros | Where-Object { $_ -and $_.Trim() -ne "" })
    } catch {
        return $false
    }
}

function Test-DockerAvailable {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $docker) {
        return $false
    }
    try {
        $info = & $docker.Source info --format "{{.OSType}}" 2>$null
        return $LASTEXITCODE -eq 0 -and ($info -eq "linux")
    } catch {
        return $false
    }
}

function Invoke-DockerLinuxBuild {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string]$OutputDir,
        [Parameter(Mandatory = $true)]
        [string]$OfflineFlag
    )

    $dockerImage = "golang:1.25-bookworm"
    Write-Host "Build Linux dist via Docker: $OutputDir (image=$dockerImage)"
    docker run --rm `
        -v "${Root}:/workspace" `
        -w /workspace `
        $dockerImage `
        bash -lc "set -euo pipefail; apt-get update; apt-get install -y --no-install-recommends pkg-config gcc g++; OFFLINE=$OfflineFlag COPY_RULES=0 bash ./scripts/build-linux.sh $OutputDir"
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Linux build failed for $OutputDir"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptDir
$offlineFlag = if ($Offline) { "1" } else { "0" }

Write-Host "Build all dist packages (offline=$Offline, windowsLinkMode=$WindowsLinkMode)"

Push-Location $root
try {
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false
    & (Join-Path $root "scripts\build-windows.ps1") -OutputDir "dist-windows-amd64-public" -Offline:$Offline -LinkMode $WindowsLinkMode -CopyRules:$false

    if (Test-WSLAvailable) {
        $rootWsl = Convert-ToWslPath -WindowsPath $root
        bash -lc "set -euo pipefail; cd '$rootWsl'; OFFLINE=$offlineFlag COPY_RULES=0 bash ./scripts/build-linux.sh dist-linux-amd64"
        bash -lc "set -euo pipefail; cd '$rootWsl'; OFFLINE=$offlineFlag COPY_RULES=0 bash ./scripts/build-linux.sh dist-linux-amd64-public"
    } elseif (Test-DockerAvailable) {
        Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-amd64" -OfflineFlag $offlineFlag
        Invoke-DockerLinuxBuild -Root $root -OutputDir "dist-linux-amd64-public" -OfflineFlag $offlineFlag
    } else {
        throw "No usable Linux build runtime found. Install WSL with a distro, or make Docker Desktop Linux containers available."
    }
}
finally {
    Pop-Location
}

Write-Host "All dist directories updated."
