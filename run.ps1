param(
  [switch]$Wait
)

$ErrorActionPreference = 'Stop'

$conda = Get-Command conda -ErrorAction SilentlyContinue
$baseArgs = @("run", "-n", "csu_auto_connect", "python", "-m", "csu_auto_connect") + $args

if ($Wait) {
  Write-Host "Launching (attached)... Exit the app from tray -> Quit."
  if ($conda) {
    conda @baseArgs
    exit $LASTEXITCODE
  }

  python -m csu_auto_connect @args
  exit $LASTEXITCODE
}

# Detached launch: avoid confusing "blank" PowerShell window for GUI apps.
if ($conda) {
  Start-Process -FilePath "conda" -ArgumentList $baseArgs -WindowStyle Hidden | Out-Null
} else {
  Start-Process -FilePath "python" -ArgumentList (@("-m", "csu_auto_connect") + $args) -WindowStyle Hidden | Out-Null
}
Write-Host "Launched CSU Auto Connect. Look for the tray icon (right-bottom)."
Write-Host "To exit: tray icon -> Quit."
