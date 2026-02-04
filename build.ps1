$ErrorActionPreference = 'Stop'

$name = 'csu_auto_connect'

# If the app is running, files in dist/workpath may be locked and cause build failures.
cmd /c "taskkill /F /IM $name.exe >nul 2>nul" | Out-Null

$distPath = Join-Path $PSScriptRoot "dist"
$workPath = Join-Path $env:TEMP "pyinstaller-$name"
$specPath = Join-Path $PSScriptRoot ".pyinstaller"

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

if ($conda) {
  conda run -n csu_auto_connect pyinstaller @pyinstallerArgs
} else {
  pyinstaller @pyinstallerArgs
}

if ($LASTEXITCODE -ne 0) {
  Write-Error "PyInstaller failed with exit code $LASTEXITCODE"
  exit $LASTEXITCODE
}

$outDir = Join-Path $distPath $name
$outExe = Join-Path $outDir "$name.exe"

Write-Host ("Built: {0}" -f $outExe)
Write-Host "NOTE: Please run the EXE from dist\\. Do NOT run anything under build\\."
Write-Host "If you copy it elsewhere, copy the whole folder (including _internal\\), not just the .exe."

if (Test-Path $outDir) {
  Start-Process explorer.exe $outDir | Out-Null
}
