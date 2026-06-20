param(
    [Parameter(Mandatory)][string]$Target,
    [string]$Mode = "default",
    [string]$Api = "http://localhost:8000"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "" ; Write-Host ">> $msg" -ForegroundColor Cyan }

function Write-FindingCard($f) {
    $sev   = $f.severity
    $color = switch ($sev) {
        "Critical" { "Red" } "High" { "DarkRed" } "Medium" { "Yellow" } default { "Gray" }
    }
    Write-Host "  +-[$sev] $($f.title)" -ForegroundColor $color
    $desc = if ($f.description.Length -gt 72) { $f.description.Substring(0,69) + "..." } else { $f.description }
    $rem  = if ($f.remediation.Length  -gt 72) { $f.remediation.Substring(0,69)  + "..." } else { $f.remediation  }
    Write-Host "  |  Issue:  $desc" -ForegroundColor Gray
    Write-Host "  |  Fix:    $rem"  -ForegroundColor Gray
    if ($f.evidence) {
        $ev = if ($f.evidence.Length -gt 72) { $f.evidence.Substring(0,69) + "..." } else { $f.evidence }
        Write-Host "  |  Evid:   $ev" -ForegroundColor DarkGray
    }
    Write-Host "  +------------------------------------------------------------------" -ForegroundColor $color
    Write-Host ""
}

# --- Consent (skipped for local/docker targets) ---
$localPatterns = @("localhost", "127.0.0.1", "host.docker.internal", "demo-target", "192.168.", "10.")
$isLocal = $localPatterns | Where-Object { $Target -like "*$_*" }

$scanBody = @{ targetUrl = $Target; scanMode = $Mode }

if (-not $isLocal) {
    Write-Step "Getting consent for $Target"
    $consent = Invoke-RestMethod -Uri "$Api/consent" -Method POST `
        -ContentType "application/json" `
        -Body (@{ targetUrl = $Target } | ConvertTo-Json -Compress)
    $scanBody["consentId"] = $consent.consentId
    Write-Host "  Consent recorded: $($consent.consentId)"
}

# --- Start scan ---
Write-Step "Starting $Mode scan against $Target"
$scan = Invoke-RestMethod -Uri "$Api/scan" -Method POST `
    -ContentType "application/json" `
    -Body ($scanBody | ConvertTo-Json -Compress)
$scanId = $scan.scanId
Write-Host "  Scan ID: $scanId"

# --- Poll until done ---
Write-Step "Waiting for scan to complete (polling every 10s)..."
$dots = 0
while ($true) {
    Start-Sleep -Seconds 10
    $status = Invoke-RestMethod -Uri "$Api/scan/$scanId"
    Write-Host -NoNewline "."
    $dots++
    if ($dots % 6 -eq 0) { Write-Host " [$($status.status), $($status.findings.Count) finding(s) so far]" }
    if ($status.status -in @("completed", "failed")) { break }
}
Write-Host ""

# --- Fetch full report (includes fixPrompt) ---
$report = Invoke-RestMethod -Uri "$Api/report/$scanId"

# --- Print findings ---
$findingCount = $report.findings.Count
Write-Step "Scan $($status.status.ToUpper()) - $findingCount finding(s)"

if ($findingCount -gt 0) {
    $sevOrder = @("Critical", "High", "Medium", "Low")
    $sorted   = $report.findings | Sort-Object { $sevOrder.IndexOf($_.severity) }
    foreach ($f in $sorted) { Write-FindingCard $f }
} else {
    Write-Host "  No findings."
}

# --- One-prompt fix ---
if ($report.fixPrompt) {
    $sep = "=" * 70
    Write-Host $sep                                                         -ForegroundColor Magenta
    Write-Host "  ONE-PROMPT FIX  --  paste into Cursor / Claude / Copilot" -ForegroundColor Magenta
    Write-Host $sep                                                         -ForegroundColor Magenta
    Write-Host ""
    Write-Host $report.fixPrompt -ForegroundColor White
    Write-Host ""
    Write-Host $sep -ForegroundColor Magenta
}

# --- Footer ---
Write-Host ""
Write-Host "Full report:  $Api/report/$scanId" -ForegroundColor Green
Write-Host "Export PDF:   Invoke-WebRequest -Uri `"$Api/report/$scanId/export`" -OutFile report.pdf" -ForegroundColor DarkGreen
