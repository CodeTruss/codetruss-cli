$ErrorActionPreference = "Stop"

$MetadataUrl = if ($env:CODETRUSS_INSTALL_METADATA_URL) {
  $env:CODETRUSS_INSTALL_METADATA_URL
} else {
  "https://codetruss.com/downloads/codetruss-cli-latest.json"
}

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "CodeTruss requires Node.js 20.9 or newer: https://nodejs.org/"
}

$NodeVersion = (& node -p 'process.versions.node').Split(".")
if (([int]$NodeVersion[0] -lt 20) -or (([int]$NodeVersion[0] -eq 20) -and ([int]$NodeVersion[1] -lt 9))) {
  throw "CodeTruss requires Node.js 20.9 or newer; found $(& node --version)."
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw "CodeTruss requires npm, which normally ships with Node.js."
}

$Scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("codetruss-cli-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $Scratch | Out-Null
$Archive = Join-Path $Scratch "codetruss-cli.tgz"

try {
  if ($env:CODETRUSS_INSTALL_URL) {
    $PackageUrl = $env:CODETRUSS_INSTALL_URL
    $ExpectedSha256 = $env:CODETRUSS_INSTALL_SHA256
    if (-not $ExpectedSha256) {
      throw "CODETRUSS_INSTALL_SHA256 is required with a custom CODETRUSS_INSTALL_URL."
    }
  } else {
    $Metadata = Invoke-RestMethod -Uri $MetadataUrl
    $PackageUrl = ([uri]::new([uri]$MetadataUrl, [string]$Metadata.url)).AbsoluteUri
    $ExpectedSha256 = [string]$Metadata.sha256
    if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
      throw "CodeTruss release metadata contains an invalid SHA-256 digest."
    }
  }

  Write-Host "Downloading CodeTruss CLI from $PackageUrl"
  Invoke-WebRequest -Uri $PackageUrl -OutFile $Archive
  # Use the .NET implementation directly instead of relying on PowerShell's
  # Microsoft.PowerShell.Utility module being discoverable. Windows PowerShell
  # can inherit a PowerShell Core PSModulePath from a parent process, which
  # prevents Get-FileHash from auto-loading even though SHA-256 is available.
  $Sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $ArchiveStream = [System.IO.File]::OpenRead($Archive)
    try {
      $ActualSha256 = ([System.BitConverter]::ToString($Sha256.ComputeHash($ArchiveStream))).Replace("-", "").ToLowerInvariant()
    } finally {
      $ArchiveStream.Dispose()
    }
  } finally {
    $Sha256.Dispose()
  }
  if ($ActualSha256 -ne $ExpectedSha256.ToLowerInvariant()) {
    throw "CodeTruss release checksum mismatch: expected $ExpectedSha256, received $ActualSha256."
  }

  Write-Host "Checksum verified: $ActualSha256"
  & npm install --global --ignore-scripts --no-audit --no-fund $Archive
  if ($LASTEXITCODE -ne 0) {
    throw "npm install failed with exit code $LASTEXITCODE"
  }
} finally {
  Remove-Item -Recurse -Force $Scratch -ErrorAction SilentlyContinue
}

$Command = Get-Command codetruss -ErrorAction SilentlyContinue
if (-not $Command) {
  Write-Host "CodeTruss installed. Restart this shell so npm's global bin directory is on PATH, then run inside your Git repository: codetruss setup"
  exit 0
}

# `Get-Command codetruss` succeeding is not the same as it being the binary just
# installed: an older install earlier in PATH shadows this one, and the hooks
# invoke `codetruss` by name. Compare where PATH resolves it against npm's global
# prefix. On Windows the shims land directly in the prefix (no bin/ subdirectory),
# so compare the directory rather than an exact file name.
function Get-NormalizedPath {
  param([string]$Path)
  if (-not $Path) { return $null }
  $Trimmed = $Path.Trim()
  if (-not $Trimmed) { return $null }
  try {
    return ([System.IO.Path]::GetFullPath($Trimmed)).TrimEnd([char[]]('\', '/'))
  } catch {
    return $Trimmed.TrimEnd([char[]]('\', '/'))
  }
}

$Prefix = if ($env:NPM_CONFIG_PREFIX) {
  $env:NPM_CONFIG_PREFIX
} else {
  (& npm prefix --global | Select-Object -First 1)
}
if ($Prefix) { $Prefix = $Prefix.Trim() }

# ApplicationInfo (.cmd) and ExternalScriptInfo (.ps1) both expose the full path
# on .Source; fall back to .Path, and skip the check if neither is present.
$ResolvedPath = if ($Command.Source) { $Command.Source } else { $Command.Path }
if ($Prefix -and $ResolvedPath) {
  $InstalledDir = Get-NormalizedPath $Prefix
  $ResolvedDir = Get-NormalizedPath (Split-Path -Parent $ResolvedPath)
  if ($InstalledDir -and $ResolvedDir -and ($InstalledDir -ine $ResolvedDir)) {
    Write-Warning "codetruss on your PATH resolves to $ResolvedPath, not the install that just completed in $Prefix."
    Write-Host "Running codetruss would use that one instead. Put $Prefix ahead of it in PATH (or remove the shadowing install), then run: codetruss setup"
    exit 0
  }
}

& codetruss --version
Write-Host "Ready. Run inside your Git repository: codetruss setup"
