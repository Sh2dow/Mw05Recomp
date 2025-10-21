param(
    [string]$RepoUrl = "https://github.com/Sh2dow/Mw05Recomp.wiki.git",
    [string]$WikiDir,
    [string]$SourceDir,
    [switch]$DryRun,
    [switch]$NoPull
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[wiki] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[wiki] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[wiki] $msg" -ForegroundColor Red }

# Defaults
if (-not $WikiDir)   { $WikiDir   = Join-Path $PSScriptRoot "..\Mw05Recomp.wiki" }
if (-not $SourceDir) { $SourceDir = Join-Path $PSScriptRoot "..\docs\wiki" }

Write-Info "RepoUrl    = $RepoUrl"
Write-Info "WikiDir    = $WikiDir"
Write-Info "SourceDir  = $SourceDir"
Write-Info "DryRun     = $($DryRun.IsPresent)"
Write-Info "NoPull     = $($NoPull.IsPresent)"

# Preflight checks
if (-not (Test-Path $SourceDir)) {
    Write-Err "SourceDir not found: $SourceDir"
    exit 1
}

# Ensure git is available
try {
    $null = & git --version
} catch {
    Write-Err "git is not available on PATH. Please install Git."
    exit 1
}

# Clone wiki repo if missing
if (-not (Test-Path $WikiDir)) {
    Write-Info "WikiDir not found, cloning..."
    if ($DryRun) {
        Write-Info "[DRY-RUN] Would run: git clone $RepoUrl `"$WikiDir`""
    } else {
        & git clone $RepoUrl "$WikiDir"
    }
} else {
    Write-Info "WikiDir exists."
    if (-not $NoPull) {
        Write-Info "Fetching latest..."
        if ($DryRun) {
            Write-Info "[DRY-RUN] Would run: git -C `"$WikiDir`" pull --ff-only"
        } else {
            & git -C "$WikiDir" pull --ff-only
        }
    }
}

# Copy wiki sources into wiki repo working dir
Write-Info "Copying files..."
$exclude = @('.git')
if ($DryRun) {
    Write-Info "[DRY-RUN] Would copy from $SourceDir to $WikiDir (recursive, excluding .git)"
} else {
    # Use PowerShell copy to avoid robocopy exit codes
    Get-ChildItem -Path $SourceDir -Recurse -Force | ForEach-Object {
        if ($exclude -contains $_.Name) { return }
        $rel = Resolve-Path -LiteralPath $_.FullName | ForEach-Object { $_.Path.Substring((Resolve-Path $SourceDir).Path.Length).TrimStart('\') }
        $dst = Join-Path $WikiDir $rel
        if ($_.PSIsContainer) {
            if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst | Out-Null }
        } else {
            $dstDir = Split-Path $dst -Parent
            if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Path $dstDir | Out-Null }
            Copy-Item -LiteralPath $_.FullName -Destination $dst -Force
        }
    }
}

# Stage changes
Write-Info "Staging changes..."
if ($DryRun) {
    Write-Info "[DRY-RUN] Would run: git -C `"$WikiDir`" add -A"
} else {
    & git -C "$WikiDir" add -A
}

# Commit if there are changes
$commitMsg = "wiki: update consolidated docs"
if ($DryRun) {
    Write-Info "[DRY-RUN] Would commit with message: $commitMsg"
} else {
    $status = (& git -C "$WikiDir" status --porcelain)
    if ([string]::IsNullOrWhiteSpace($status)) {
        Write-Warn "No changes to commit."
    } else {
        & git -C "$WikiDir" commit -m $commitMsg
    }
}

# Push
if ($DryRun) {
    Write-Info "[DRY-RUN] Would push to origin"
} else {
    $status = (& git -C "$WikiDir" status --porcelain)
    if ([string]::IsNullOrWhiteSpace($status)) {
        Write-Info "Nothing to push (repo up-to-date)."
    } else {
        & git -C "$WikiDir" push
    }
}

Write-Info "Done."
