[CmdletBinding()]
param(
    [int]$HttpPort = 18080,
    [int]$HttpsPort = 18443
)

$ErrorActionPreference = 'Stop'
$projectName = "jellyfin-proxy-m2-$PID"
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
$policyFile = Join-Path $PSScriptRoot 'whitelist.caddy.generated'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$subnetOctet = 1 + ($PID % 250)
$subnetPrefix = "172.29.$subnetOctet"
$trustedIP = "$subnetPrefix.10"
$untrustedIP = "$subnetPrefix.20"

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

function Parse-CurlOutput([string[]]$Output, [string]$Request) {
    $lines = @($Output -split "`r?`n")
    if ($lines.Count -lt 1) {
        throw "curl returned no status for $Request"
    }
    $statusCode = 0
    if (-not [int]::TryParse($lines[-1], [ref]$statusCode)) {
        throw "curl returned an invalid status for $Request"
    }
    $content = if ($lines.Count -gt 1) { $lines[0..($lines.Count - 2)] -join "`n" } else { '' }
    [pscustomobject]@{ StatusCode = $statusCode; Content = $content }
}

function Get-LocalResponse([string]$Scheme, [int]$Port, [string]$HostName, [string]$Path = '/') {
    $uri = "${Scheme}://${HostName}:${Port}${Path}"
    $resolve = "${HostName}:${Port}:127.0.0.1"
    $output = & curl.exe --noproxy '*' --silent --show-error --insecure --resolve $resolve --write-out "`n%{http_code}" $uri
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $uri with exit code $LASTEXITCODE"
    }
    Parse-CurlOutput -Output $output -Request $uri
}

function Set-WhitelistPolicy([string[]]$Entries) {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $generated = & go run ./tests/integration/policygen @Entries
    }
    else {
        $repoPath = $repoRoot.Replace('\', '/')
        $arguments = @('run', '--rm', '-v', "${repoPath}:/src", '-w', '/src', 'golang:1.25.2-alpine3.22', 'go', 'run', './tests/integration/policygen')
        $arguments += $Entries
        $generated = & docker @arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Whitelist Caddy policy generation failed with exit code $LASTEXITCODE"
    }
    [System.IO.File]::WriteAllText($policyFile, (@($generated) -join "`n") + "`n")
}

function Get-ClientResponse([string]$Service, [string]$Path, [string]$ForwardedFor = '') {
    $uri = "https://access.domain.test$Path"
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-to', 'access.domain.test:443:caddy:443')
    if ($ForwardedFor) {
        $curlArgs += @('--header', "X-Forwarded-For: $ForwardedFor")
    }
    $curlArgs += @('--write-out', "`n%{http_code}", $uri)
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY $Service curl @curlArgs
    if ($LASTEXITCODE -ne 0) {
        throw "curl from $Service failed for $uri with exit code $LASTEXITCODE"
    }
    Parse-CurlOutput -Output $output -Request "$Service $uri"
}

function Get-MockRequestCount {
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY trusted-client curl --noproxy '*' --silent --show-error http://jellyfin-mock:8096/__requests
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read mock request count (exit $LASTEXITCODE)."
    }
    [string]$output | ForEach-Object { $_.Trim() }
}

Push-Location $repoRoot
try {
    $env:HTTP_PORT = [string]$HttpPort
    $env:HTTPS_PORT = [string]$HttpsPort
    $env:TEST_SUBNET = "$subnetPrefix.0/24"
    $env:TRUSTED_CLIENT_IP = $trustedIP
    $env:UNTRUSTED_CLIENT_IP = $untrustedIP
    Set-WhitelistPolicy -Entries @()

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
    $emptyAllowedClient = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$emptyAllowedClient.StatusCode) 'Empty whitelist did not deny the trusted test client.'
    $emptyUntrustedClient = Get-ClientResponse -Service 'untrusted-client' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$emptyUntrustedClient.StatusCode) 'Empty whitelist did not deny the untrusted test client.'
    Assert-Equal '0' (Get-MockRequestCount) 'An empty whitelist forwarded an unauthorized request to mock Jellyfin.'

    $allowedNetwork = "$subnetPrefix.8/29"
    Set-WhitelistPolicy -Entries @($allowedNetwork)
    Invoke-Compose exec --no-TTY caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile

    $allowed = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '200' ([string][int]$allowed.StatusCode) 'Whitelisted client did not reach mock Jellyfin.'
    $jellyfin = $allowed.Content | ConvertFrom-Json
    Assert-Equal 'Jellyfin' $jellyfin.ProductName 'Allowed access route returned the wrong upstream.'
    Assert-Equal 'local-test-jellyfin' $jellyfin.ServerName 'Allowed access route returned the wrong mock server.'

    $spoofed = Get-ClientResponse -Service 'untrusted-client' -Path '/System/Info/Public' -ForwardedFor $trustedIP
    Assert-Equal '403' ([string][int]$spoofed.StatusCode) 'Spoofed X-Forwarded-For bypassed the whitelist.'
    $hostClient = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'access.domain.test' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$hostClient.StatusCode) 'An unlisted host client reached Jellyfin.'
    Assert-Equal '1' (Get-MockRequestCount) 'A denied request was unexpectedly forwarded to mock Jellyfin.'

    $composeRows = Invoke-Compose ps --format json
    $mockRows = @($composeRows | ForEach-Object { $_ | ConvertFrom-Json })
    $mock = $mockRows | Where-Object { $_.Service -eq 'jellyfin-mock' } | Select-Object -First 1
    if (-not $mock) {
        throw 'Compose did not report the mock Jellyfin service.'
    }
    $inspection = (& docker inspect $mock.ID | ConvertFrom-Json)[0]
    if ($inspection.NetworkSettings.Ports.'8096/tcp') {
        throw 'Mock Jellyfin unexpectedly has a published host port.'
    }

    Write-Host 'M2 integration checks passed: host routing, default deny, IPv4 CIDR client allow, spoofed-header rejection, and no mock exposure.'
}
finally {
    try {
        Invoke-Compose down --remove-orphans --volumes --rmi local
    }
    finally {
        Remove-Item $policyFile -ErrorAction SilentlyContinue
        Remove-Item Env:HTTP_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:TEST_SUBNET -ErrorAction SilentlyContinue
        Remove-Item Env:TRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Remove-Item Env:UNTRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Pop-Location
    }
}
