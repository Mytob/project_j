[CmdletBinding()]
param(
    [int]$HttpPort = 18080,
    [int]$HttpsPort = 18443
)

$ErrorActionPreference = 'Stop'
$projectName = "jellyfin-proxy-m1-$PID"
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

function Invoke-Compose {
    & docker compose --project-name $projectName --file $composeFile @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

function Assert-Equal([string]$Expected, [string]$Actual, [string]$Message) {
    if ($Expected -cne $Actual) {
        throw "$Message`nExpected: $Expected`nActual:   $Actual"
    }
}

function Get-LocalResponse([string]$Scheme, [int]$Port, [string]$HostName, [string]$Path = '/') {
	$uri = "${Scheme}://${HostName}:${Port}${Path}"
	$resolve = "${HostName}:${Port}:127.0.0.1"
	$output = & curl.exe --noproxy '*' --silent --show-error --insecure --resolve $resolve --write-out "`n%{http_code}" $uri
	if ($LASTEXITCODE -ne 0) {
		throw "curl failed for $uri with exit code $LASTEXITCODE"
	}
	$lines = @($output -split "`r?`n")
	if ($lines.Count -lt 1) {
		throw "curl returned no status for $uri"
	}
	$statusCode = 0
	if (-not [int]::TryParse($lines[-1], [ref]$statusCode)) {
		throw "curl returned an invalid status for $uri"
	}
	$content = if ($lines.Count -gt 1) { $lines[0..($lines.Count - 2)] -join "`n" } else { '' }
	[pscustomobject]@{ StatusCode = $statusCode; Content = $content }
}

Push-Location $repoRoot
try {
    $env:HTTP_PORT = [string]$HttpPort
    $env:HTTPS_PORT = [string]$HttpsPort
    Invoke-Compose up --build --detach

    $deadline = (Get-Date).AddSeconds(60)
    $httpReady = $false
    while ((Get-Date) -lt $deadline) {
        try {
            $httpCheck = Get-LocalResponse -Scheme 'http' -Port $HttpPort -HostName 'domain.test'
            $httpReady = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $httpReady) {
        throw 'Caddy did not become ready within 60 seconds.'
    }

    Assert-Equal '308' ([string][int]$httpCheck.StatusCode) 'Base hostname did not redirect HTTP to HTTPS.'
    $site = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'domain.test'
    Assert-Equal '200' ([string][int]$site.StatusCode) 'Base hostname HTTPS did not serve the site.'
    if ($site.Content -notmatch 'local Milestone 1 static site') {
        throw 'Base hostname returned unexpected site content.'
    }

    $adminHttp = Get-LocalResponse -Scheme 'http' -Port $HttpPort -HostName 'admin.domain.test'
    Assert-Equal '308' ([string][int]$adminHttp.StatusCode) 'Admin hostname did not redirect HTTP to HTTPS.'
    $admin = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'admin.domain.test'
    Assert-Equal '503' ([string][int]$admin.StatusCode) 'Admin hostname did not reach the M1 placeholder route.'

    $accessHttp = Get-LocalResponse -Scheme 'http' -Port $HttpPort -HostName 'access.domain.test'
    Assert-Equal '308' ([string][int]$accessHttp.StatusCode) 'Access hostname did not redirect HTTP to HTTPS.'
    $access = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'access.domain.test' -Path '/System/Info/Public'
    Assert-Equal '200' ([string][int]$access.StatusCode) 'Access hostname did not proxy to mock Jellyfin.'
    $jellyfin = $access.Content | ConvertFrom-Json
    Assert-Equal 'Jellyfin' $jellyfin.ProductName 'Access hostname returned the wrong upstream.'
    Assert-Equal 'local-test-jellyfin' $jellyfin.ServerName 'Access hostname returned the wrong mock server.'

    $mockPorts = (Invoke-Compose ps --format json) | ForEach-Object { $_ | ConvertFrom-Json }
    $mock = $mockPorts | Where-Object { $_.Service -eq 'jellyfin-mock' } | Select-Object -First 1
    if (-not $mock) {
        throw 'Compose did not report the mock Jellyfin service.'
    }
    $inspection = (& docker inspect $mock.ID | ConvertFrom-Json)[0]
    if ($inspection.NetworkSettings.Ports.'8096/tcp') {
        throw 'Mock Jellyfin unexpectedly has a published host port.'
    }

    Write-Host 'M1 integration checks passed: HTTP-to-HTTPS redirects for all three hostnames, HTTPS routing, static content, Jellyfin proxy, and no published mock port.'
}
finally {
    try {
        Invoke-Compose down --remove-orphans --volumes --rmi local
    }
    finally {
        Remove-Item Env:HTTP_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PORT -ErrorAction SilentlyContinue
        Pop-Location
    }
}
