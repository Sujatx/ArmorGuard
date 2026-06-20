param(
    [Parameter(Mandatory)][string]$Target,
    [string]$Mode = "default",
    [string]$Api = "http://localhost:8000"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "" ; Write-Host ">> $msg" -ForegroundColor Cyan }
function Write-Finding($sev, $title) {
    $color = switch ($sev) {
        "Critical" { "Red" } "High" { "DarkRed" } "Medium" { "Yellow" } default { "Gray" }
    }
    Write-Host "  [$sev] $title" -ForegroundColor $color
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

# --- Print results ---
$findingCount = $status.findings.Count
Write-Step "Scan $($status.status.ToUpper()) - $findingCount finding(s)"
if ($findingCount -gt 0) {
    $status.findings | Sort-Object { @("Critical","High","Medium","Low").IndexOf($_.severity) } |
        ForEach-Object { Write-Finding $_.severity $_.title }
} else {
    Write-Host "  No findings."
}

Write-Host ""
$reportUrl = "$Api/report/$scanId"
Write-Host "Full report: $reportUrl" -ForegroundColor Green
