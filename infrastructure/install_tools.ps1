# ArmorGuard — Security Tool Installer (Windows)
# Run from the repo root: .\scripts\install_tools.ps1

$ErrorActionPreference = "Stop"
$binDir = "$env:USERPROFILE\.local\bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

# Add to user PATH if not already there
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$binDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$currentPath;$binDir", "User")
}
$env:PATH = "$env:PATH;$binDir"

function Download-GHRelease($repo, $filePattern, $outName) {
    Write-Host "Downloading $outName..."
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
    $asset   = $release.assets | Where-Object { $_.name -like $filePattern } | Select-Object -First 1
    if (-not $asset) { Write-Error "No asset matching '$filePattern' in $repo"; return }
    $tmp = "$env:TEMP\$outName.zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmp -UseBasicParsing
    Expand-Archive -Path $tmp -DestinationPath "$env:TEMP\${outName}_tmp" -Force
    $exe = Get-ChildItem "$env:TEMP\${outName}_tmp" -Filter "*.exe" -Recurse | Select-Object -First 1
    Copy-Item $exe.FullName "$binDir\$outName.exe" -Force
    Remove-Item $tmp, "$env:TEMP\${outName}_tmp" -Recurse -Force
    Write-Host "$outName installed → $binDir\$outName.exe"
}

# nmap
Write-Host "`n=== nmap ==="
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command nmap).Source)"
} else {
    winget install Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
    Write-Host "nmap installed"
}

# nuclei
Write-Host "`n=== nuclei ==="
if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command nuclei).Source)"
} else {
    Download-GHRelease "projectdiscovery/nuclei" "*windows_amd64.zip" "nuclei"
}

# httpx (ProjectDiscovery)
Write-Host "`n=== httpx (ProjectDiscovery) ==="
if (Get-Command httpx -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command httpx).Source)"
} else {
    Download-GHRelease "projectdiscovery/httpx" "*windows_amd64.zip" "httpx"
}

# katana (ProjectDiscovery crawler — discovery stage)
Write-Host "`n=== katana ==="
if (Get-Command katana -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command katana).Source)"
} else {
    Download-GHRelease "projectdiscovery/katana" "*windows_amd64.zip" "katana"
}

# ffuf (route brute-forcer — discovery)
Write-Host "`n=== ffuf ==="
if (Get-Command ffuf -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command ffuf).Source)"
} else {
    Download-GHRelease "ffuf/ffuf" "*windows_amd64.zip" "ffuf"
}

# sqlmap + arjun (pip console entrypoints — match the backend image)
Write-Host "`n=== sqlmap + arjun ==="
if (Get-Command sqlmap -ErrorAction SilentlyContinue) {
    Write-Host "Already installed: $((Get-Command sqlmap).Source)"
} else {
    pip install --upgrade sqlmap
}
pip install --upgrade arjun
# NOTE: nikto is Perl-based and easiest under WSL/Linux; the backend Docker image
# installs it via apt. On native Windows, run nikto through WSL if you need it locally.

# nuclei templates
Write-Host "`n=== nuclei templates ==="
nuclei -update-templates 2>&1 | Select-Object -Last 3

Write-Host "`nAll tools ready (nmap, nuclei, httpx, sqlmap). Restart your terminal for PATH changes to take effect."
