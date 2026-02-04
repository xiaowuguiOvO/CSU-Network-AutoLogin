$ErrorActionPreference = 'Stop'

$name = 'csu_auto_connect'

# Best-effort stop (ignore errors)
cmd /c "taskkill /F /IM $name.exe >nul 2>nul" | Out-Null

foreach ($dir in @("dist", "build", ".pyinstaller", "release", ".venv")) {
  $p = Join-Path $PSScriptRoot $dir
  if (Test-Path $p) {
    cmd /c "rmdir /s /q `"$p`"" | Out-Null
  }
}

Get-ChildItem -Path $PSScriptRoot -Recurse -Force -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue | ForEach-Object {
  cmd /c "rmdir /s /q `"$($_.FullName)`"" | Out-Null
}

Get-ChildItem -Path $PSScriptRoot -Recurse -Force -File -Include "*.pyc","*.log","*.spec" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "Cleaned build artifacts."

