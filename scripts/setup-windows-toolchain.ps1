param(
    [string]$InstallDir = "third_party\toolchain",
    [string]$ReleaseTag = "",
    [string]$ArchivePath = "",
    [string]$ChecksumPath = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $scriptRoot

$toolchainRoot = Join-Path $root $InstallDir
$targetDir = Join-Path $toolchainRoot "mingw64"
$targetGcc = Join-Path $targetDir "bin\gcc.exe"
$tmpDir = Join-Path $root ".tmp\toolchain"
$extractRoot = Join-Path $tmpDir "extract"

if ((Test-Path $targetGcc) -and -not $Force) {
    Write-Host "Toolchain already installed: $targetGcc"
    exit 0
}

New-Item -ItemType Directory -Force $tmpDir | Out-Null

function Resolve-InputPath {
    param([string]$InputPath)

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        return ""
    }
    if (Test-Path $InputPath) {
        return (Resolve-Path $InputPath).Path
    }

    $candidate = Join-Path $root $InputPath
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }
    throw "path not found: $InputPath"
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string[]]$Urls,
        [Parameter(Mandatory = $true)][string]$OutFile
    )

    foreach ($url in $Urls) {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            Write-Host "Download attempt ${attempt}: $url"
            & curl.exe -L --fail --retry 4 --retry-delay 5 --retry-all-errors -C - -o $OutFile $url
            if ($LASTEXITCODE -eq 0 -and (Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) {
                return
            }
            Start-Sleep -Seconds (5 * $attempt)
        }

        Write-Host "curl download failed for $url, trying BITS transfer..."
        try {
            Start-BitsTransfer -Source $url -Destination $OutFile -TransferType Download
            if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) {
                return
            }
        } catch {
            Write-Host "BITS failed for ${url}: $($_.Exception.Message)"
        }
    }
    throw "download failed for all URLs"
}

function Verify-Checksum {
    param(
        [Parameter(Mandatory = $true)][string]$Archive,
        [Parameter(Mandatory = $true)][string]$ChecksumFile
    )

    $expected = (Get-Content $ChecksumFile -Raw).Trim().Split()[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch. expected=$expected actual=$actual"
    }
    Write-Host "Checksum verified."
}

$archiveToExtract = ""
$checksumToUse = ""

if (-not [string]::IsNullOrWhiteSpace($ArchivePath)) {
    $archiveToExtract = Resolve-InputPath $ArchivePath
    if (-not $archiveToExtract.ToLowerInvariant().EndsWith(".zip")) {
        throw "ArchivePath must point to a .zip file."
    }
    Write-Host "Using local archive: $archiveToExtract"

    if (-not [string]::IsNullOrWhiteSpace($ChecksumPath)) {
        $checksumToUse = Resolve-InputPath $ChecksumPath
    }
} else {
    if ($ReleaseTag) {
        $metaURL = "https://api.github.com/repos/brechtsanders/winlibs_mingw/releases/tags/$ReleaseTag"
    } else {
        $metaURL = "https://api.github.com/repos/brechtsanders/winlibs_mingw/releases/latest"
    }

    Write-Host "Fetching release metadata: $metaURL"
    $release = Invoke-RestMethod -Uri $metaURL

    $asset = $release.assets | Where-Object {
        $_.name -like "winlibs-x86_64-posix-seh-gcc-*.zip" -and
        $_.name -notlike "*.sha256" -and
        $_.name -notlike "*.sha512"
    } | Select-Object -First 1

    if (-not $asset) {
        throw "Could not find x86_64 winlibs zip asset in release $($release.tag_name)."
    }

    $shaAsset = $release.assets | Where-Object { $_.name -eq "$($asset.name).sha256" } | Select-Object -First 1

    $archiveToExtract = Join-Path $tmpDir $asset.name
    $sourceforgeAssetURL = "https://sourceforge.net/projects/winlibs-mingw/files/$($release.tag_name)/$($asset.name)/download"

    Write-Host "Downloading toolchain archive..."
    Download-File -Urls @($sourceforgeAssetURL, $asset.browser_download_url) -OutFile $archiveToExtract

    if ($shaAsset) {
        $checksumToUse = Join-Path $tmpDir "$($asset.name).sha256"
        $sourceforgeShaURL = "https://sourceforge.net/projects/winlibs-mingw/files/$($release.tag_name)/$($shaAsset.name)/download"
        Write-Host "Downloading checksum..."
        Download-File -Urls @($sourceforgeShaURL, $shaAsset.browser_download_url) -OutFile $checksumToUse
    }
}

if (-not [string]::IsNullOrWhiteSpace($checksumToUse)) {
    Verify-Checksum -Archive $archiveToExtract -ChecksumFile $checksumToUse
}

if (Test-Path $extractRoot) {
    Remove-Item -Recurse -Force $extractRoot
}
New-Item -ItemType Directory -Force $extractRoot | Out-Null

Write-Host "Extracting archive..."
Expand-Archive -Path $archiveToExtract -DestinationPath $extractRoot -Force

$gcc = Get-ChildItem -Path $extractRoot -Recurse -Filter gcc.exe |
    Where-Object { $_.FullName -match "\\bin\\gcc\.exe$" } |
    Select-Object -First 1

if (-not $gcc) {
    throw "gcc.exe not found after extraction."
}

$sourceRoot = Split-Path -Parent (Split-Path -Parent $gcc.FullName)

New-Item -ItemType Directory -Force $toolchainRoot | Out-Null
if (Test-Path $targetDir) {
    Remove-Item -Recurse -Force $targetDir
}

Write-Host "Installing to project: $targetDir"
robocopy $sourceRoot $targetDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path $targetGcc)) {
    throw "installation completed but gcc not found at $targetGcc"
}

Write-Host "Installed toolchain: $targetGcc"
