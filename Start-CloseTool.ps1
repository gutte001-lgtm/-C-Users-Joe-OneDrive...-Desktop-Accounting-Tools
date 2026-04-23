# CloseTool launcher for PowerShell.
#
# Why this file exists: the project folder lives under
# "C:\Users\Joe\OneDrive - Healthcare Markets DBA\Desktop\Accounting Tools",
# which has spaces AND a dash. Pasting that path bare into PowerShell makes
# PS parse the first token ("C:\Users\Joe\OneDrive") as a command and fail
# with "is not recognized as the name of a cmdlet". This launcher's filename
# has no spaces, and it uses $PSScriptRoot so it doesn't care where the
# folder lives — run it from anywhere with:
#
#   & "C:\path\to\Start-CloseTool.ps1"
#
# or just double-click it (right-click → Run with PowerShell).

$ErrorActionPreference = 'Stop'

$Host.UI.RawUI.WindowTitle = 'CloseTool - Running'
Set-Location -LiteralPath $PSScriptRoot

# Open the browser after a short delay, in the background, so the server
# has time to bind :5000 before the tab loads.
Start-Job -ScriptBlock {
    Start-Sleep -Seconds 3
    Start-Process 'http://127.0.0.1:5000'
} | Out-Null

Write-Host 'Starting CloseTool...'
Write-Host ''
Write-Host "Open http://127.0.0.1:5000 in your browser if it doesn't open automatically."
Write-Host 'Press Ctrl+C to stop the server.'
Write-Host ''

# Prefer the Python launcher (py), fall back to python on PATH.
$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Host '--- Python not found on PATH. Install Python 3 from https://python.org, then re-run. ---'
    Read-Host 'Press Enter to close'
    exit 1
}

& $python.Source app.py

Write-Host ''
Write-Host '--- Server stopped ---'
Read-Host 'Press Enter to close'
