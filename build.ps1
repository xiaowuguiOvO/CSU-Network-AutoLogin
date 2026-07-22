$ErrorActionPreference = 'Stop'

$name = 'csu_auto_connect'

# If the app is running, files in dist/workpath may be locked and cause build failures.
cmd /c "taskkill /F /IM $name.exe >nul 2>nul" | Out-Null

$distPath = Join-Path $PSScriptRoot "dist"
$workPath = Join-Path $env:TEMP "pyinstaller-$name"
$specPath = Join-Path $PSScriptRoot ".pyinstaller"
$outDir = Join-Path $distPath $name
$savedConfig = Join-Path $outDir "config.ini"
$configBackup = $null

# PyInstaller recreates the output directory. Preserve the local user's settings.
if (Test-Path -LiteralPath $savedConfig) {
  $configBackup = New-TemporaryFile
  Copy-Item -LiteralPath $savedConfig -Destination $configBackup.FullName -Force
}

$conda = Get-Command conda -ErrorAction SilentlyContinue

$pyinstallerArgs = @(
  "--noconsole",
  "--name", $name,
  "--clean",
  "--noconfirm",
  "--distpath", $distPath,
  "--workpath", $workPath,
  "--specpath", $specPath,
  "csu_auto_connect\\main.py"
)

try {
  if ($conda) {
    conda run -n csu_auto_connect pyinstaller @pyinstallerArgs
  } else {
    pyinstaller @pyinstallerArgs
  }

  if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
  }
} finally {
  if ($configBackup -and (Test-Path -LiteralPath $configBackup.FullName)) {
    if (Test-Path -LiteralPath $outDir) {
      Copy-Item -LiteralPath $configBackup.FullName -Destination $savedConfig -Force
    }
    Remove-Item -LiteralPath $configBackup.FullName -Force
  }
}

$outExe = Join-Path $outDir "$name.exe"

Write-Host ("Built: {0}" -f $outExe)
Write-Host "NOTE: Please run the EXE from dist\\. Do NOT run anything under build\\."
Write-Host "If you copy it elsewhere, copy the whole folder (including _internal\\), not just the .exe."

if (Test-Path $outDir) {
  Start-Process explorer.exe $outDir | Out-Null
}
