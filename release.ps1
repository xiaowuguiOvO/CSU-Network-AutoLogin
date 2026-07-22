param(
  [string]$Version
)

$ErrorActionPreference = 'Stop'

function Get-VersionFromPyProject {
  $path = Join-Path $PSScriptRoot "pyproject.toml"
  if (-not (Test-Path $path)) {
    throw "pyproject.toml not found"
  }
  foreach ($line in Get-Content -Encoding UTF8 $path) {
    if ($line -match '^\s*version\s*=\s*\"([^\"]+)\"') {
      return $Matches[1].Trim()
    }
  }
  throw 'version not found in pyproject.toml (expected: version = "x.y.z")'
}

if (-not $Version) {
  $Version = Get-VersionFromPyProject
}

Write-Host "Building..."
& "$PSScriptRoot\\build.ps1"

$distDir = Join-Path $PSScriptRoot "dist\\csu_auto_connect"
if (-not (Test-Path $distDir)) {
  throw "dist folder not found: $distDir"
}

# Add a couple of helpful files into the portable folder for release packaging.
Copy-Item -Force (Join-Path $PSScriptRoot "config.example.ini") (Join-Path $distDir "config.example.ini")
Copy-Item -Force (Join-Path $PSScriptRoot "README.md") (Join-Path $distDir "README.md")

$releaseDir = Join-Path $PSScriptRoot "release"
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null

$zipName = "csu_auto_connect-v$Version-windows-x64.zip"
$zipPath = Join-Path $releaseDir $zipName
if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}

$userConfig = Join-Path $distDir "config.ini"
$configBackup = $null
if (Test-Path -LiteralPath $userConfig) {
  $configBackup = New-TemporaryFile
  Copy-Item -LiteralPath $userConfig -Destination $configBackup.FullName -Force
  Remove-Item -LiteralPath $userConfig -Force
}

try {
  Compress-Archive -Path $distDir -DestinationPath $zipPath
} finally {
  Remove-Item -Force (Join-Path $distDir "config.example.ini") -ErrorAction SilentlyContinue
  Remove-Item -Force (Join-Path $distDir "README.md") -ErrorAction SilentlyContinue
  if ($configBackup -and (Test-Path -LiteralPath $configBackup.FullName)) {
    Copy-Item -LiteralPath $configBackup.FullName -Destination $userConfig -Force
    Remove-Item -LiteralPath $configBackup.FullName -Force
  }
}

$hash = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash.ToLower()
$hashPath = Join-Path $releaseDir ($zipName + ".sha256.txt")
Set-Content -Encoding ASCII -Path $hashPath -Value ("{0}  {1}" -f $hash, $zipName)

Write-Host "Release zip: $zipPath"
Write-Host "SHA256: $hashPath"
Start-Process explorer.exe $releaseDir | Out-Null
