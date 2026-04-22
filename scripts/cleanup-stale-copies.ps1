# cleanup-stale-copies.ps1
#
# Safely inspects and optionally removes the stale CloseTool copies and the
# bogus home-folder .git that accumulated across earlier agent sessions.
#
# USAGE (run from inside the canonical project folder in PowerShell):
#   powershell -ExecutionPolicy Bypass -File .\scripts\cleanup-stale-copies.ps1
#
# It never deletes anything without asking. Answer "y" to confirm each step.
# Run "git status" before starting to confirm you have no uncommitted work
# you want to save.

$ErrorActionPreference = 'Stop'

function Ask($prompt) {
    $ans = Read-Host "$prompt [y/N]"
    return $ans -eq 'y' -or $ans -eq 'Y'
}

Write-Host ""
Write-Host "=== CloseTool stale-copy cleanup ===" -ForegroundColor Cyan
Write-Host ""

# --- 1. Home-folder .git ---------------------------------------------------
$homeGit = "C:\Users\Joe\.git"
if (Test-Path $homeGit) {
    Write-Host "[1] Found a git repo at C:\Users\Joe\.git" -ForegroundColor Yellow
    Write-Host "    This means your entire user profile is a git repo, which is"
    Write-Host "    almost certainly a mistake. Inspecting its log first so you"
    Write-Host "    can see if there is anything worth keeping:"
    Write-Host ""
    Push-Location C:\Users\Joe
    try {
        git log --oneline -10 2>&1 | Out-Host
        $branch = git rev-parse --abbrev-ref HEAD 2>&1
        Write-Host ""
        Write-Host "    Current branch in that repo: $branch"
    } finally {
        Pop-Location
    }
    Write-Host ""
    if (Ask "    Delete C:\Users\Joe\.git? (The actual CloseTool repo is NOT affected.)") {
        Remove-Item -Recurse -Force $homeGit
        Write-Host "    Deleted C:\Users\Joe\.git" -ForegroundColor Green
    } else {
        Write-Host "    Skipped." -ForegroundColor DarkGray
    }
} else {
    Write-Host "[1] No C:\Users\Joe\.git found. Good." -ForegroundColor Green
}
Write-Host ""

# --- 2. Stray app.py copies -----------------------------------------------
$strayPaths = @(
    "C:\Users\Joe\app.py",
    "C:\Users\Joe\Downloads\app.py"
)
foreach ($p in $strayPaths) {
    if (Test-Path $p) {
        $size = (Get-Item $p).Length
        $mtime = (Get-Item $p).LastWriteTime
        Write-Host "[2] Stray app.py: $p  ($size bytes, modified $mtime)" -ForegroundColor Yellow
        if (Ask "    Delete this file?") {
            Remove-Item -Force $p
            Write-Host "    Deleted." -ForegroundColor Green
        } else {
            Write-Host "    Skipped." -ForegroundColor DarkGray
        }
    }
}

# --- 3. Old close-tracker prototype ---------------------------------------
$oldProj = "C:\Users\Joe\Desktop\Claude Projects\close-tracker"
if (Test-Path $oldProj) {
    Write-Host "[3] Old prototype folder: $oldProj" -ForegroundColor Yellow
    Write-Host "    Contents:"
    Get-ChildItem $oldProj | Select-Object Name, Length, LastWriteTime | Format-Table | Out-Host
    if (Ask "    Delete the entire close-tracker folder?") {
        Remove-Item -Recurse -Force $oldProj
        Write-Host "    Deleted." -ForegroundColor Green
    } else {
        Write-Host "    Skipped." -ForegroundColor DarkGray
    }
} else {
    Write-Host "[3] No close-tracker folder found. Good." -ForegroundColor Green
}

# --- 4. In-project scratch files ------------------------------------------
$projectRoot = git rev-parse --show-toplevel 2>$null
if ($projectRoot) {
    $projectRoot = $projectRoot.Trim()
    $patterns = @("app.OLD.py", "app_new.py", "debug_recon*.py", "test_email.py", "test_login.py",
                  "Hello.py", "frontend_api.jsx", "export_report.py", "read_transactions.py",
                  "AGENT_CONTEXT.md", "SETUP.md")
    $found = @()
    foreach ($pat in $patterns) {
        $found += Get-ChildItem -Path $projectRoot -Filter $pat -File -ErrorAction SilentlyContinue
    }
    if ($found.Count -gt 0) {
        Write-Host ""
        Write-Host "[4] Scratch files inside the project root:" -ForegroundColor Yellow
        $found | Select-Object Name, Length, LastWriteTime | Format-Table | Out-Host
        Write-Host "    These are leftovers from earlier agent sessions."
        if (Ask "    Delete all of the above?") {
            $found | Remove-Item -Force
            Write-Host "    Deleted." -ForegroundColor Green
        } else {
            Write-Host "    Skipped." -ForegroundColor DarkGray
        }
    } else {
        Write-Host ""
        Write-Host "[4] No scratch files in project root. Good." -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Done. Run 'git status' to see the current state." -ForegroundColor Cyan
