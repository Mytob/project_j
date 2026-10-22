[CmdletBinding()]
param(
    [int]$HttpPort = 0,
    [int]$HttpsPort = 0,
    [switch]$UpdateBrowserSnapshots
)

$ErrorActionPreference = 'Stop'
$projectName = "jellyfin-proxy-m6-$PID"
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
$policyFile = Join-Path $PSScriptRoot 'whitelist.caddy.generated'
$credentialFile = Join-Path $PSScriptRoot 'admin-credential.generated.json'
$wireguardConfigDir = Join-Path $PSScriptRoot 'wireguard.generated'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$subnetOctet = 1 + ($PID % 250)
$subnetPrefix = "172.29.$subnetOctet"
$trustedIP = "$subnetPrefix.10"
$untrustedIP = "$subnetPrefix.20"
$browserIP = "$subnetPrefix.30"
$wireguardIP = "$subnetPrefix.2"
$securitydIP = "$subnetPrefix.40"
$adminIP = "$subnetPrefix.50"
$hostMetricsIP = "$subnetPrefix.60"
$homePeerIP = "$subnetPrefix.70"
$securityBaseImage = "jellyfin-proxy/security-integration-base:$PID"
$securityTestImage = "jellyfin-proxy/security-integration:$PID"

function Get-AvailableLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return [int]$listener.LocalEndpoint.Port
    }
    finally {
        $listener.Stop()
    }
}

if ($HttpPort -eq 0) { $HttpPort = Get-AvailableLoopbackPort }
if ($HttpsPort -eq 0) {
    do { $HttpsPort = Get-AvailableLoopbackPort } while ($HttpsPort -eq $HttpPort)
}
if ($HttpPort -lt 1 -or $HttpPort -gt 65535 -or $HttpsPort -lt 1 -or $HttpsPort -gt 65535 -or $HttpPort -eq $HttpsPort) {
    throw 'HTTP and HTTPS integration ports must be distinct TCP ports in the range 1 through 65535.'
}

function Invoke-Compose {
    & docker compose --project-name $projectName --file $composeFile @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "docker $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

function Invoke-IntegrationGate([string]$ScriptPath) {
    & pwsh -NoProfile -File $ScriptPath
    if ($LASTEXITCODE -ne 0) { throw "Integration gate $ScriptPath failed with exit code $LASTEXITCODE" }
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
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $output = & curl.exe --noproxy '*' --silent --show-error --insecure --connect-timeout 3 --max-time 8 --resolve $resolve --write-out "`n%{http_code}" $uri
        if ($LASTEXITCODE -eq 0) { return Parse-CurlOutput -Output $output -Request $uri }
        if ($attempt -lt 10) { Start-Sleep -Milliseconds 300 }
    }
    throw "curl failed for $uri after 10 attempts with exit code $LASTEXITCODE"
}

function Set-WhitelistPolicy([string[]]$Entries) {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        $generated = & go run ./tests/integration/policygen @Entries
    }
    else {
        $repoPath = $repoRoot.Replace('\', '/')
        $arguments = @('run', '--rm', '-v', "${repoPath}:/src", '-w', '/src', 'golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d', 'go', 'run', './tests/integration/policygen')
        $arguments += $Entries
        $generated = & docker @arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Whitelist Caddy policy generation failed with exit code $LASTEXITCODE"
    }
    [System.IO.File]::WriteAllText($policyFile, (@($generated) -join "`n") + "`n")
}

function New-TestCredential {
    $password = 'integration-test-admin-password'
    # A previous run can be interrupted before its finally block removes this
    # generated fixture. Remove that stale file or bind-mount directory before
    # atomically creating the new credential on Windows-backed Docker volumes.
    if (Test-Path -LiteralPath $credentialFile) {
        Remove-Item -LiteralPath $credentialFile -Force -Recurse
    }
    if (Get-Command go -ErrorAction SilentlyContinue) {
        & go run ./tests/integration/credentialgen --output $credentialFile --password $password
    }
    else {
        $repoPath = $repoRoot.Replace('\', '/')
        & docker run --rm -v "${repoPath}:/src" -w /src golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d go run ./tests/integration/credentialgen --output ./tests/integration/admin-credential.generated.json --password $password
    }
    if ($LASTEXITCODE -ne 0) { throw "Test credential generation failed with exit code $LASTEXITCODE" }
    # Windows bind mounts may map the generated owner-only file to an unrelated
    # container UID. This fixture contains only the disposable integration password.
    $repoPath = $repoRoot.Replace('\', '/')
    & docker run --rm -v "${repoPath}:/src" alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 chmod 644 /src/tests/integration/admin-credential.generated.json
    if ($LASTEXITCODE -ne 0) { throw "Test credential fixture permissions could not be set (exit $LASTEXITCODE)" }
}

function Invoke-AdminRequest([string]$Path, [string]$Method, [string]$CookieJar, [string]$CSRF = '', [string]$Password = '', [string]$Entry = '', [string]$Name = '') {
    $uri = "https://admin.domain.test:${HttpsPort}${Path}"
    $resolve = "admin.domain.test:${HttpsPort}:127.0.0.1"
    $headersPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.headers')
    $bodyPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.body')
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-timeout', '3', '--max-time', '8', '--resolve', $resolve, '--cookie', $CookieJar, '--cookie-jar', $CookieJar, '--dump-header', $headersPath, '--output', $bodyPath)
    if ($Method -eq 'POST') {
        $curlArgs += @('--request', 'POST', '--data-urlencode', "csrf=$CSRF")
        if ($Path -eq '/login') { $curlArgs += @('--data-urlencode', "password=$Password") }
        if ($Path -eq '/whitelist/add' -or $Path -eq '/whitelist/remove' -or $Path -eq '/whitelist/name') { $curlArgs += @('--data-urlencode', "entry=$Entry") }
        if ($Path -eq '/whitelist/add' -or $Path -eq '/whitelist/name') { $curlArgs += @('--data-urlencode', "name=$Name") }
    }
    $curlArgs += @('--write-out', '%{http_code}', $uri)
    $status = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "curl failed for $uri with exit code $LASTEXITCODE" }
    $code = 0
    if (-not [int]::TryParse([string]$status, [ref]$code)) { throw "curl returned an invalid status for $uri" }
    [pscustomobject]@{ StatusCode = $code; Body = [System.IO.File]::ReadAllText($bodyPath); Headers = [System.IO.File]::ReadAllText($headersPath) }
}

function Invoke-AdminJSON([string]$Path, [string]$CookieJar, [string]$CSRF, [string]$Body) {
    $uri = "https://admin.domain.test:${HttpsPort}${Path}"
    $resolve = "admin.domain.test:${HttpsPort}:127.0.0.1"
    $headersPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.headers')
    $bodyPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.body')
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-timeout', '3', '--max-time', '8', '--resolve', $resolve, '--cookie', $CookieJar, '--cookie-jar', $CookieJar, '--dump-header', $headersPath, '--output', $bodyPath, '--request', 'POST', '--header', 'Content-Type: application/json', '--header', "X-CSRF-Token: $CSRF", '--data-raw', $Body, '--write-out', '%{http_code}', $uri)
    $status = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "curl failed for $uri with exit code $LASTEXITCODE" }
    $code = 0
    if (-not [int]::TryParse([string]$status, [ref]$code)) { throw "curl returned an invalid status for $uri" }
    [pscustomobject]@{ StatusCode = $code; Body = [System.IO.File]::ReadAllText($bodyPath); Headers = [System.IO.File]::ReadAllText($headersPath) }
}

function Get-AdminInitial([string]$CookieJar) {
    $response = Invoke-AdminRequest -Path '/api/initial' -Method 'GET' -CookieJar $CookieJar
    Assert-Equal '200' ([string][int]$response.StatusCode) 'Authenticated admin state API was unavailable.'
    $response.Body | ConvertFrom-Json
}

function Get-ClientResponse([string]$Service, [string]$Path, [string]$ForwardedFor = '') {
    $uri = "https://access.domain.test$Path"
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-timeout', '3', '--max-time', '8', '--connect-to', 'access.domain.test:443:wireguard:443')
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

function Get-ClientAdminResponse([string]$Service, [string]$Path) {
    $uri = "https://admin.domain.test$Path"
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-timeout', '3', '--max-time', '8', '--connect-to', 'admin.domain.test:443:wireguard:443', '--write-out', "`n%{http_code}", $uri)
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY $Service curl @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "Admin request from $Service failed for $uri with exit code $LASTEXITCODE" }
    Parse-CurlOutput -Output $output -Request "$Service $uri"
}

function Invoke-ClientLogin([string]$Service, [string]$Password, [string]$CookieName) {
    $cookiePath = "/tmp/jp-security-$CookieName.cookies"
    $uri = 'https://admin.domain.test/'
    $common = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--connect-timeout', '3', '--max-time', '8', '--connect-to', 'admin.domain.test:443:wireguard:443')
    $page = & docker compose --project-name $projectName --file $composeFile exec --no-TTY $Service curl @common --cookie-jar $cookiePath --write-out "`n%{http_code}" $uri
    if ($LASTEXITCODE -ne 0) { throw "Could not start the direct admin login test for $Service." }
    $pageText = [string]($page -join "`n")
    $statusBreak = $pageText.LastIndexOf("`n")
    if ($statusBreak -lt 0) { throw "Direct admin sign-in page from $Service omitted its HTTP status." }
    $pageStatus = $pageText.Substring($statusBreak + 1).Trim()
    $pageBody = $pageText.Substring(0, $statusBreak)
    $csrf = [regex]::Match($pageBody, 'name="csrf" value="([^"]+)"').Groups[1].Value
    if (-not $csrf) {
        $preview = ($pageBody -replace '\s+', ' ').Trim()
        if ($preview.Length -gt 180) { $preview = $preview.Substring(0, 180) }
        throw "Admin sign-in page did not provide a CSRF token to $Service (HTTP $pageStatus): $preview"
    }
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY $Service curl @common --cookie $cookiePath --cookie-jar $cookiePath --request POST --data-urlencode "csrf=$csrf" --data-urlencode "password=$Password" --output /dev/null --write-out '%{http_code}' https://admin.domain.test/login
    if ($LASTEXITCODE -ne 0) { throw "Direct admin login request from $Service failed." }
    $status = 0
    if (-not [int]::TryParse([string]($output -join '').Trim(), [ref]$status)) { throw "Direct admin login from $Service returned an invalid status." }
    $status
}

function Get-MockRequestCount {
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard-check curl --noproxy '*' --silent --show-error --connect-timeout 3 --max-time 8 http://10.66.66.2:8096/__requests
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read mock request count (exit $LASTEXITCODE)."
    }
    [string]$output | ForEach-Object { $_.Trim() }
}

function New-WireGuardTestConfigs {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        & go run ./tests/integration/wireguardgen --directory $wireguardConfigDir --endpoint 'wireguard:51820'
    }
    else {
        $repoPath = $repoRoot.Replace('\', '/')
        & docker run --rm -v "${repoPath}:/src" -w /src golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d go run ./tests/integration/wireguardgen --directory ./tests/integration/wireguard.generated --endpoint 'wireguard:51820'
    }
    if ($LASTEXITCODE -ne 0) { throw "WireGuard test config generation failed with exit code $LASTEXITCODE" }
}

function Get-WireGuardHealth([int]$TimeoutSeconds = 2) {
    $maxTimeSeconds = $TimeoutSeconds + 1
    $output = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard-check curl --noproxy '*' --fail --silent --show-error --connect-timeout $TimeoutSeconds --max-time $maxTimeSeconds http://10.66.66.2:8096/health
    [pscustomobject]@{ Healthy = ($LASTEXITCODE -eq 0 -and ([string]$output).Trim() -eq 'ok'); Output = [string]$output }
}

Push-Location $repoRoot
try {
    $env:HTTP_PORT = [string]$HttpPort
    $env:HTTPS_PORT = [string]$HttpsPort
    $env:TEST_SUBNET = "$subnetPrefix.0/24"
    $env:TRUSTED_CLIENT_IP = $trustedIP
    $env:UNTRUSTED_CLIENT_IP = $untrustedIP
    $env:BROWSER_TEST_IP = $browserIP
    $env:WIREGUARD_IP = $wireguardIP
    $env:SECURITYD_IP = $securitydIP
    $env:ADMIN_IP = $adminIP
    $env:HOSTMETRICS_IP = $hostMetricsIP
    $env:HOME_PEER_IP = $homePeerIP
    $env:SECURITY_TEST_IMAGE = $securityTestImage
    $env:BROWSER_SNAPSHOT_MODE = if ($UpdateBrowserSnapshots) { 'all' } else { 'missing' }
    Set-WhitelistPolicy -Entries @()
    $script:adminTempDir = Join-Path $env:TEMP "jellyfin-proxy-admin-test-$PID"
    New-Item -ItemType Directory -Path $adminTempDir -Force | Out-Null
    New-TestCredential
    New-WireGuardTestConfigs

    Invoke-IntegrationGate (Join-Path $PSScriptRoot 'security-caddy.ps1')
    Invoke-IntegrationGate (Join-Path $PSScriptRoot 'security-firewall.ps1')
    Invoke-Docker @('build', '--file', (Join-Path $repoRoot 'deploy/security/Dockerfile'), '--tag', $securityBaseImage, $repoRoot)
    Invoke-Docker @('build', '--file', (Join-Path $PSScriptRoot 'Dockerfile.security-test'), '--build-arg', "BASE_IMAGE=$securityBaseImage", '--tag', $securityTestImage, $repoRoot)

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

    $wireguardDeadline = (Get-Date).AddSeconds(30)
    $wireguardReady = $false
    while ((Get-Date) -lt $wireguardDeadline) {
        $probe = Get-WireGuardHealth -TimeoutSeconds 2
        if ($probe.Healthy) { $wireguardReady = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $wireguardReady) {
        $serverState = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard wg show 2>&1
        $serverRoutes = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard ip route 2>&1
        $serverFirewall = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard iptables -nvL JELLYFIN_PROXY_INPUT 2>&1
        $peerState = & docker compose --project-name $projectName --file $composeFile exec --no-TTY home-peer wg show 2>&1
        $peerRoutes = & docker compose --project-name $projectName --file $composeFile exec --no-TTY home-peer ip route 2>&1
        throw "Home mock Jellyfin was not reachable through WireGuard: $($probe.Output)`nServer peer:`n$($serverState -join "`n")`nServer routes:`n$($serverRoutes -join "`n")`nServer ingress rules:`n$($serverFirewall -join "`n")`nClient peer:`n$($peerState -join "`n")`nClient routes:`n$($peerRoutes -join "`n")"
    }
    Invoke-Compose exec --no-TTY wireguard wg-quick down /etc/wireguard/wg0.conf
    $outage = Get-WireGuardHealth -TimeoutSeconds 2
    if ($outage.Healthy) { throw 'WireGuard outage check still reached home Jellyfin.' }
    Invoke-Compose exec --no-TTY wireguard wg-quick up /etc/wireguard/wg0.conf
    # The server interface lost its peer endpoint when it went down; send one
    # packet from the initiating home peer to trigger a fresh handshake.
    & docker compose --project-name $projectName --file $composeFile exec --no-TTY home-peer ping -c 1 -W 2 10.66.66.1 2>&1 | Out-Null
    $recoveryDeadline = (Get-Date).AddSeconds(15)
    $wireguardRecovered = $false
    while ((Get-Date) -lt $recoveryDeadline) {
        $probe = Get-WireGuardHealth -TimeoutSeconds 2
        if ($probe.Healthy) { $wireguardRecovered = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $wireguardRecovered) {
        $serverState = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard wg show
        $peerState = & docker compose --project-name $projectName --file $composeFile exec --no-TTY home-peer wg show
        $serverRoutes = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard ip route
        throw "WireGuard did not recover. Server state:`n$($serverState -join "`n")`nPeer state:`n$($peerState -join "`n")`nRoutes:`n$($serverRoutes -join "`n")"
    }

    Assert-Equal '308' ([string][int]$httpCheck.StatusCode) 'Base hostname did not redirect HTTP to HTTPS.'
    $site = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'domain.test'
    Assert-Equal '200' ([string][int]$site.StatusCode) 'Base hostname HTTPS did not serve the site.'
    if ($site.Content -notmatch 'local Milestone 1 static site') {
        throw 'Base hostname returned unexpected site content.'
    }

    $adminHttp = Get-LocalResponse -Scheme 'http' -Port $HttpPort -HostName 'admin.domain.test'
    Assert-Equal '308' ([string][int]$adminHttp.StatusCode) 'Admin hostname did not redirect HTTP to HTTPS.'
    $adminJar = Join-Path $adminTempDir 'admin.cookies'
    $unauthorized = Invoke-AdminRequest -Path '/dashboard' -Method 'GET' -CookieJar $adminJar
    if ($unauthorized.StatusCode -eq 502) {
        $adminLogs = & docker compose --project-name $projectName --file $composeFile logs admin
        throw "Admin service returned 502. Container logs:`n$($adminLogs -join "`n")"
    }
    Assert-Equal '303' ([string][int]$unauthorized.StatusCode) 'Unauthenticated admin dashboard did not redirect to sign-in.'
    $anonymousWireGuard = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar
    Assert-Equal '303' ([string][int]$anonymousWireGuard.StatusCode) 'Unauthenticated request downloaded the WireGuard config.'
    $loginPage = Invoke-AdminRequest -Path '/' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '200' ([string][int]$loginPage.StatusCode) 'Admin sign-in page was unavailable.'
    $csrfMatch = [regex]::Match($loginPage.Body, 'name="csrf" value="([^"]+)"')
    if (-not $csrfMatch.Success) { throw 'Admin sign-in page did not include a CSRF token.' }
    if ($loginPage.Headers -notmatch '(?i)Set-Cookie: admin_session=.*HttpOnly;.*Secure;.*SameSite=Strict') { throw 'Admin session cookie is missing HttpOnly, Secure, or SameSite=Strict.' }
    if ($loginPage.Headers -notmatch '(?i)Cache-Control: no-store') { throw 'Admin sign-in page is cacheable.' }
    $csrf = $csrfMatch.Groups[1].Value
    $badCsrf = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $adminJar -CSRF 'invalid' -Password 'integration-test-admin-password'
    Assert-Equal '403' ([string][int]$badCsrf.StatusCode) 'Admin login accepted an invalid CSRF token.'
    $wrongPassword = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $adminJar -CSRF $csrf -Password 'wrong-integration-password'
    Assert-Equal '401' ([string][int]$wrongPassword.StatusCode) 'Admin login accepted a wrong password.'
    $login = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $adminJar -CSRF $csrf -Password 'integration-test-admin-password'
    Assert-Equal '303' ([string][int]$login.StatusCode) 'Valid administrator password did not sign in.'
    $dashboard = Invoke-AdminRequest -Path '/dashboard' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '200' ([string][int]$dashboard.StatusCode) 'Authenticated administrator could not open dashboard.'
    $adminState = Get-AdminInitial -CookieJar $adminJar
    $components = @($adminState.components)
    foreach ($component in @('Admin backend', 'Access control', 'Caddy / proxy', 'WireGuard interface', 'Windows peer', 'Jellyfin endpoint', 'Host metrics', 'Proxy metrics', 'Admin container', 'Host metrics container', 'Caddy container', 'WireGuard container')) {
        if ($components.name -notcontains $component) { throw "Overview did not report component '$component'." }
    }
    foreach ($component in @('Windows peer', 'Jellyfin endpoint')) {
        $entry = $components | Where-Object name -eq $component | Select-Object -First 1
        Assert-Equal 'Healthy' $entry.state "$component did not report its observed healthy state."
    }
    foreach ($component in @('Admin container', 'Host metrics container', 'Caddy container', 'WireGuard container')) {
        $entry = $components | Where-Object name -eq $component | Select-Object -First 1
        Assert-Equal 'Healthy' $entry.state "$component did not report its Docker healthcheck state."
        if ($entry.detail -notmatch 'health healthy' -or $entry.detail -notmatch 'restarts') { throw "$component did not include Docker health and restart evidence." }
    }
    $securityReadyDeadline = (Get-Date).AddSeconds(35)
    $securityReady = $false
    while ((Get-Date) -lt $securityReadyDeadline) {
        $adminState = Get-AdminInitial -CookieJar $adminJar
        $securityHealth = $adminState.security.health
        if ($securityHealth.fail2ban -eq 'healthy' -and $securityHealth.ssh_journal -eq 'healthy' -and $securityHealth.firewall -eq 'healthy' -and $securityHealth.admin_events -eq 'healthy' -and $securityHealth.caddy_sync -eq 'healthy') { $securityReady = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $securityReady) { throw "Security services did not become healthy: $($adminState.security.health | ConvertTo-Json -Compress)" }

    $trustedPeerEntry = "$trustedIP/32"
    $securityCsrf = $adminState.csrf
    $trustedPeerAdd = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $securityCsrf -Entry $trustedPeerEntry -Name 'Security integration peer'
    Assert-Equal '303' ([string][int]$trustedPeerAdd.StatusCode) 'Could not allow the isolated test client for the Jellyfin isolation check.'
	$trustedAdminDeadline = (Get-Date).AddSeconds(8)
	$trustedAdminPage = $null
	do {
		$trustedAdminPage = Get-ClientAdminResponse -Service 'trusted-client' -Path '/'
		if ([int]$trustedAdminPage.StatusCode -eq 200) { break }
		Start-Sleep -Milliseconds 150
	} while ((Get-Date) -lt $trustedAdminDeadline)
	Assert-Equal '200' ([string]$trustedAdminPage.StatusCode) 'Caddy did not apply the newly added trusted test address before its admin authentication checks.'

    foreach ($attempt in 1..2) {
        $result = Invoke-ClientLogin -Service 'untrusted-client' -Password 'wrong-security-test-password' -CookieName 'reset-check'
        Assert-Equal '401' ([string]$result) "Admin source success-reset failure $attempt returned an unexpected status."
    }
    $resetObserved = $false
    $resetDeadline = (Get-Date).AddSeconds(12)
    while ((Get-Date) -lt $resetDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        if ($state.security.pending_failures -ge 2) { $resetObserved = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $resetObserved) { throw 'Two failed logins from the independent test source were not processed.' }
    $successStatus = Invoke-ClientLogin -Service 'untrusted-client' -Password 'integration-test-admin-password' -CookieName 'reset-check'
    Assert-Equal '303' ([string]$successStatus) 'Valid admin login did not complete after the source-reset failures.'
    $resetDeadline = (Get-Date).AddSeconds(12)
    $resetObserved = $false
    while ((Get-Date) -lt $resetDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        $untrustedBan = @($state.security.active_bans | Where-Object { $_.service -eq 'admin' -and $_.ip -eq $untrustedIP })
        if ($state.security.pending_failures -eq 0 -and $untrustedBan.Count -eq 0) { $resetObserved = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $resetObserved) { throw 'A valid login did not clear only that source IP pending admin failures.' }

    foreach ($attempt in 1..3) {
        $result = Invoke-ClientLogin -Service 'trusted-client' -Password 'wrong-security-test-password' -CookieName 'admin-ban'
        Assert-Equal '401' ([string]$result) "Admin ban source failure $attempt returned an unexpected status."
    }
    $banDeadline = (Get-Date).AddSeconds(15)
    $trustedBan = @()
    while ((Get-Date) -lt $banDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        $trustedBan = @($state.security.active_bans | Where-Object { $_.service -eq 'admin' -and $_.ip -eq $trustedIP })
        if ($trustedBan.Count -eq 1) { break }
        Start-Sleep -Milliseconds 300
    }
    if ($trustedBan.Count -ne 1) { throw "Three signed admin failures did not create a ban for $trustedIP." }
    # Signed auth events are consumed asynchronously by securityd. Wait for its
    # event-driven Caddy snapshot update before asserting the network-visible
    # effect, while keeping the propagation bound small and explicit.
    $adminBanDeadline = (Get-Date).AddSeconds(3)
    $blockedAdmin = $null
    do {
        $blockedAdmin = Get-ClientAdminResponse -Service 'trusted-client' -Path '/'
        if ([int]$blockedAdmin.StatusCode -eq 403) { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $adminBanDeadline)
    Assert-Equal '403' ([string]$blockedAdmin.StatusCode) 'Caddy did not block the banned source from the admin hostname.'
    if ($blockedAdmin.Content -notmatch 'Access Denied') { throw 'Banned administrator response did not contain Access Denied.' }
    $unaffectedJellyfin = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '200' ([string]$unaffectedJellyfin.StatusCode) 'An admin ban also blocked the Jellyfin access route.'
    $mockRequestBaseline = [int](Get-MockRequestCount)
    $securityHistory = Invoke-AdminRequest -Path '/security/history?range=24h&service=admin' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '200' ([string][int]$securityHistory.StatusCode) 'Authenticated admin security history was unavailable.'
    $securityRows = @($securityHistory.Body | ConvertFrom-Json)
    if (@($securityRows | Where-Object { $_.ip -eq $trustedIP -and $_.type -eq 'failure' }).Count -lt 3 -or @($securityRows | Where-Object { $_.ip -eq $trustedIP -and $_.type -eq 'ban' }).Count -ne 1) { throw 'Security history did not retain the source failures and ban event.' }
    if (@($securityRows | Where-Object { $_.type -eq 'login_success' }).Count -ne 0) { throw 'Successful administrator sign-ins appeared in retained security history.' }

    Invoke-Compose restart securityd
    $recoveryDeadline = (Get-Date).AddSeconds(25)
    $securityRecovered = $false
    while ((Get-Date) -lt $recoveryDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        $securityHealth = $state.security.health
        $trustedBan = @($state.security.active_bans | Where-Object { $_.service -eq 'admin' -and $_.ip -eq $trustedIP })
        if ($trustedBan.Count -eq 1 -and $securityHealth.fail2ban -eq 'healthy' -and $securityHealth.firewall -eq 'healthy' -and $securityHealth.admin_events -eq 'healthy' -and $securityHealth.caddy_sync -eq 'healthy') { $securityRecovered = $true; break }
        Start-Sleep -Milliseconds 400
    }
    if (-not $securityRecovered) { throw "Persisted security state did not recover after restarting securityd: $($state.security.health | ConvertTo-Json -Compress)" }
    Invoke-Compose restart caddy
    $caddyRecovered = $false
    $recoveryDeadline = (Get-Date).AddSeconds(25)
    while ((Get-Date) -lt $recoveryDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        if ($state.security.health.caddy_sync -eq 'healthy') { $caddyRecovered = $true; break }
        Start-Sleep -Milliseconds 400
    }
    if (-not $caddyRecovered) { throw 'Caddy did not resynchronize the persisted administrator ban after restart.' }
    if ($state.security.health.last_error) { throw "Recovered security services still report a stale error: $($state.security.health.last_error)" }
    # caddy_sync may still show the last successful observation while Caddy is
    # restarting. Require the network-visible block to recover as well; the
    # controller reconciles the persisted snapshot on its next one-second pass.
    $blockedAfterRestart = $null
    $blockRecoveryDeadline = (Get-Date).AddSeconds(5)
    do {
        $blockedAfterRestart = Get-ClientAdminResponse -Service 'trusted-client' -Path '/'
        if ([int]$blockedAfterRestart.StatusCode -eq 403) { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $blockRecoveryDeadline)
    Assert-Equal '403' ([string]$blockedAfterRestart.StatusCode) 'Caddy restart lost the active administrator blocklist.'

    $securityCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $unbanBody = @{ service = 'admin'; ip = $trustedIP } | ConvertTo-Json -Compress
    $securityUnban = Invoke-AdminJSON -Path '/security/unban' -CookieJar $adminJar -CSRF $securityCsrf -Body $unbanBody
    Assert-Equal '200' ([string]$securityUnban.StatusCode) 'Admin could not manually remove the integration ban.'
    $unbanDeadline = (Get-Date).AddSeconds(5)
    $unblockedAdmin = $null
    do {
        $unblockedAdmin = Get-ClientAdminResponse -Service 'trusted-client' -Path '/'
        if ([int]$unblockedAdmin.StatusCode -eq 200) { break }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $unbanDeadline)
    Assert-Equal '200' ([string]$unblockedAdmin.StatusCode) 'Manual unban did not restore admin access without a Caddy restart.'
    $untrustedLoginAfterUnban = Invoke-ClientLogin -Service 'trusted-client' -Password 'integration-test-admin-password' -CookieName 'admin-ban'
    Assert-Equal '303' ([string]$untrustedLoginAfterUnban) 'Unbanned administrator source could not sign in successfully.'
    $securityCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $trustedPeerRemove = Invoke-AdminRequest -Path '/whitelist/remove' -Method 'POST' -CookieJar $adminJar -CSRF $securityCsrf -Entry $trustedPeerEntry
    Assert-Equal '303' ([string][int]$trustedPeerRemove.StatusCode) 'Could not restore the initially empty test allowlist.'

    $securityState = Get-AdminInitial -CookieJar $adminJar
    $securityConfig = $securityState.security.config
    $securityConfig.admin.threshold = 100
    $updateConfigBody = $securityConfig | ConvertTo-Json -Depth 10 -Compress
    $securityConfigUpdate = Invoke-AdminJSON -Path '/security/config' -CookieJar $adminJar -CSRF $securityState.csrf -Body $updateConfigBody
    Assert-Equal '200' ([string]$securityConfigUpdate.StatusCode) 'Valid security configuration could not be saved through the authenticated API.'
    $securityConfig.admin.threshold = 0
    $invalidConfig = Invoke-AdminJSON -Path '/security/config' -CookieJar $adminJar -CSRF $securityState.csrf -Body ($securityConfig | ConvertTo-Json -Depth 10 -Compress)
    Assert-Equal '400' ([string]$invalidConfig.StatusCode) 'Security API accepted an out-of-range failure threshold.'
    $savedConfig = Get-AdminInitial -CookieJar $adminJar
    Assert-Equal '100' ([string]$savedConfig.security.config.admin.threshold) 'Invalid security configuration changed the active threshold.'

    $wireguardPage = Invoke-AdminRequest -Path '/wireguard' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '200' ([string][int]$wireguardPage.StatusCode) 'Authenticated administrator could not open the WireGuard page.'
    if ($wireguardPage.Body -notmatch '/app-assets/assets/') { throw 'WireGuard route did not serve the embedded React application.' }
    $wireguardCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $wireguardDownload = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar -CSRF $wireguardCsrf
    Assert-Equal '200' ([string][int]$wireguardDownload.StatusCode) 'Authenticated administrator could not download the Windows WireGuard config.'
    if ($wireguardDownload.Headers -notmatch '(?i)Content-Disposition: attachment; filename="jellyfin-proxy.conf"') { throw 'WireGuard config response lacks an attachment filename.' }
    if ($wireguardDownload.Headers -notmatch '(?i)Content-Type: application/octet-stream') { throw 'WireGuard config response has an unexpected content type.' }
    if ($wireguardDownload.Headers -notmatch '(?i)Cache-Control: no-store') { throw 'WireGuard config download is cacheable.' }
    foreach ($expected in @('[Interface]', 'Address = 10.66.66.2/32', 'Endpoint = wireguard:51820', 'AllowedIPs = 10.66.66.1/32', 'PersistentKeepalive = 25')) {
        if ($wireguardDownload.Body -notmatch [regex]::Escape($expected)) { throw "WireGuard config download is missing '$expected'." }
    }
    $wireguardDownloadAgain = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar -CSRF $wireguardCsrf
    Assert-Equal '503' ([string][int]$wireguardDownloadAgain.StatusCode) 'A second one-time WireGuard download unexpectedly succeeded.'
    $logoutState = Get-AdminInitial -CookieJar $adminJar
    $logout = Invoke-AdminRequest -Path '/logout' -Method 'POST' -CookieJar $adminJar -CSRF $logoutState.csrf
    Assert-Equal '303' ([string][int]$logout.StatusCode) 'Administrator logout did not redirect.'
    $afterLogout = Invoke-AdminRequest -Path '/dashboard' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '303' ([string][int]$afterLogout.StatusCode) 'Logged-out administrator session remained valid.'

    $throttleJar = Join-Path $adminTempDir 'throttle.cookies'
    $throttlePage = Invoke-AdminRequest -Path '/' -Method 'GET' -CookieJar $throttleJar
    $throttleCsrf = [regex]::Match($throttlePage.Body, 'name="csrf" value="([^"]+)"').Groups[1].Value
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $attemptResponse = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $throttleJar -CSRF $throttleCsrf -Password 'wrong-integration-password'
        Assert-Equal '401' ([string][int]$attemptResponse.StatusCode) "Bad password attempt $attempt did not return the generic login failure."
    }
    $throttled = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $throttleJar -CSRF $throttleCsrf -Password 'integration-test-admin-password'
    Assert-Equal '429' ([string][int]$throttled.StatusCode) 'Repeated bad passwords did not trigger login throttling.'
    Invoke-Compose restart admin

    $accessHttp = Get-LocalResponse -Scheme 'http' -Port $HttpPort -HostName 'access.domain.test'
    Assert-Equal '308' ([string][int]$accessHttp.StatusCode) 'Access hostname did not redirect HTTP to HTTPS.'
    $emptyAllowedClient = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$emptyAllowedClient.StatusCode) 'Empty whitelist did not deny the trusted test client.'
    $emptyUntrustedClient = Get-ClientResponse -Service 'untrusted-client' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$emptyUntrustedClient.StatusCode) 'Empty whitelist did not deny the untrusted test client.'
    Assert-Equal ([string]$mockRequestBaseline) (Get-MockRequestCount) 'An empty whitelist forwarded an unauthorized request to mock Jellyfin.'

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
    Assert-Equal ([string]($mockRequestBaseline + 1)) (Get-MockRequestCount) 'A denied request was unexpectedly forwarded to mock Jellyfin.'

    $freshLoginPage = Invoke-AdminRequest -Path '/' -Method 'GET' -CookieJar $adminJar
    $freshCsrf = [regex]::Match($freshLoginPage.Body, 'name="csrf" value="([^"]+)"').Groups[1].Value
    $freshLogin = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $adminJar -CSRF $freshCsrf -Password 'integration-test-admin-password'
    Assert-Equal '303' ([string][int]$freshLogin.StatusCode) 'Admin could not sign in after service restart.'
    $wireguardAfterRestartCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $wireguardAfterRestart = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar -CSRF $wireguardAfterRestartCsrf
    Assert-Equal '503' ([string][int]$wireguardAfterRestart.StatusCode) 'Admin restart unexpectedly restored a consumed one-time WireGuard config.'
    $restoredSecurity = Get-AdminInitial -CookieJar $adminJar
    $defaultSecurityConfig = $restoredSecurity.security.config
    $defaultSecurityConfig.admin.threshold = 3
    $restoreThreshold = Invoke-AdminJSON -Path '/security/config' -CookieJar $adminJar -CSRF $restoredSecurity.csrf -Body ($defaultSecurityConfig | ConvertTo-Json -Depth 10 -Compress)
    Assert-Equal '200' ([string]$restoreThreshold.StatusCode) 'Admin protection default threshold could not be restored after rate-limit coverage.'

    foreach ($attempt in 1..3) {
        $result = Invoke-ClientLogin -Service 'untrusted-client' -Password 'wrong-security-test-password' -CookieName 'ui-ban'
        Assert-Equal '401' ([string]$result) "Security UI ban setup failure $attempt returned an unexpected status."
    }
    $uiBanDeadline = (Get-Date).AddSeconds(15)
    $uiBan = @()
    while ((Get-Date) -lt $uiBanDeadline) {
        $state = Get-AdminInitial -CookieJar $adminJar
        $uiBan = @($state.security.active_bans | Where-Object { $_.service -eq 'admin' -and $_.ip -eq $untrustedIP })
        if ($uiBan.Count -eq 1) { break }
        Start-Sleep -Milliseconds 300
    }
    if ($uiBan.Count -ne 1) { throw 'Could not create an isolated active admin ban for browser unban coverage.' }
    $emptyAccessPage = Invoke-AdminRequest -Path '/access-control' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '200' ([string][int]$emptyAccessPage.StatusCode) 'Whitelist management page was unavailable.'
    $emptyState = Get-AdminInitial -CookieJar $adminJar
    $configuredEntries = @($emptyState.whitelist | ForEach-Object { [string]$_ } | Where-Object { $_.Length -gt 0 })
    if ($configuredEntries.Count -gt 0) { throw "Persistent whitelist unexpectedly contained entries before management tests: $($configuredEntries -join ', ')." }
    $managementCsrf = $emptyState.csrf
    $invalidAdd = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $managementCsrf -Entry 'bad.example'
    Assert-Equal '400' ([string][int]$invalidAdd.StatusCode) 'Admin accepted an invalid whitelist entry.'
    $addNetwork = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $managementCsrf -Entry $allowedNetwork -Name 'Home network'
    Assert-Equal '303' ([string][int]$addNetwork.StatusCode) 'Admin could not add a valid IPv4 CIDR entry.'
    $namedEntry = @((Get-AdminInitial -CookieJar $adminJar).whitelist_entries | Where-Object { $_.address -eq $allowedNetwork })
    if ($namedEntry.Count -ne 1 -or $namedEntry[0].name -ne 'Home network') { throw 'Admin did not return the friendly name for the added whitelist entry.' }
    $renameCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $renameNetwork = Invoke-AdminRequest -Path '/whitelist/name' -Method 'POST' -CookieJar $adminJar -CSRF $renameCsrf -Entry $allowedNetwork -Name 'Family devices'
    Assert-Equal '303' ([string][int]$renameNetwork.StatusCode) 'Admin could not update a whitelist friendly name.'
    $duplicateAdd = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $managementCsrf -Entry $allowedNetwork
    Assert-Equal '409' ([string][int]$duplicateAdd.StatusCode) 'Admin did not reject a duplicate entry.'
    $managedAccessPage = Invoke-AdminRequest -Path '/access-control' -Method 'GET' -CookieJar $adminJar
    if (@((Get-AdminInitial -CookieJar $adminJar).whitelist) -notcontains $allowedNetwork) { throw 'Added CIDR entry was not displayed canonically.' }
    $managedAllowed = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '200' ([string][int]$managedAllowed.StatusCode) 'Caddy did not activate the admin-added CIDR entry.'
    Invoke-Compose restart admin
    $afterRestart = Invoke-AdminRequest -Path '/dashboard' -Method 'GET' -CookieJar $adminJar
    Assert-Equal '303' ([string][int]$afterRestart.StatusCode) 'Admin session survived process restart.'
    $reloginPage = Invoke-AdminRequest -Path '/' -Method 'GET' -CookieJar $adminJar
    $reloginCsrf = [regex]::Match($reloginPage.Body, 'name="csrf" value="([^"]+)"').Groups[1].Value
    $relogin = Invoke-AdminRequest -Path '/login' -Method 'POST' -CookieJar $adminJar -CSRF $reloginCsrf -Password 'integration-test-admin-password'
    Assert-Equal '303' ([string][int]$relogin.StatusCode) 'Admin could not sign in after persistence restart check.'
    $persistedAccessPage = Invoke-AdminRequest -Path '/access-control' -Method 'GET' -CookieJar $adminJar
    $persistedState = Get-AdminInitial -CookieJar $adminJar
    if (@($persistedState.whitelist) -notcontains $allowedNetwork) { throw 'Whitelist entry did not persist across admin restart.' }
    $persistedNamedEntry = @($persistedState.whitelist_entries | Where-Object { $_.address -eq $allowedNetwork })
    if ($persistedNamedEntry.Count -ne 1 -or $persistedNamedEntry[0].name -ne 'Family devices') { throw 'Whitelist friendly name did not persist across admin restart.' }
    $persistedAllowed = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '200' ([string][int]$persistedAllowed.StatusCode) 'Caddy did not restore the persisted whitelist after admin restart.'
    $removeCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $removeNetwork = Invoke-AdminRequest -Path '/whitelist/remove' -Method 'POST' -CookieJar $adminJar -CSRF $removeCsrf -Entry $allowedNetwork
    Assert-Equal '303' ([string][int]$removeNetwork.StatusCode) 'Admin could not remove a whitelist entry.'
    $removedDenied = Get-ClientResponse -Service 'trusted-client' -Path '/System/Info/Public'
    Assert-Equal '403' ([string][int]$removedDenied.StatusCode) 'Removing the whitelist entry did not immediately deny access.'
    $emptyAccessPageAgain = Invoke-AdminRequest -Path '/access-control' -Method 'GET' -CookieJar $adminJar
    $remainingEntries = @((Get-AdminInitial -CookieJar $adminJar).whitelist | ForEach-Object { [string]$_ } | Where-Object { $_.Length -gt 0 })
    if ($remainingEntries.Count -gt 0) { throw "Removed whitelist entry remains in the admin list: $($remainingEntries -join ', ')." }
    Assert-Equal ([string]($mockRequestBaseline + 3)) (Get-MockRequestCount) 'Denied post-removal request was unexpectedly forwarded to mock Jellyfin.'

    $addIPv6 = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $removeCsrf -Entry '2001:db8::/64'
    Assert-Equal '303' ([string][int]$addIPv6.StatusCode) 'Admin could not add an IPv6 CIDR entry.'
    $ipv6AccessPage = Invoke-AdminRequest -Path '/access-control' -Method 'GET' -CookieJar $adminJar
    if (@((Get-AdminInitial -CookieJar $adminJar).whitelist) -notcontains '2001:db8::/64') { throw 'IPv6 entry was not displayed.' }
    $removeIPv6Csrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $removeIPv6 = Invoke-AdminRequest -Path '/whitelist/remove' -Method 'POST' -CookieJar $adminJar -CSRF $removeIPv6Csrf -Entry '2001:db8::/64'
    Assert-Equal '303' ([string][int]$removeIPv6.StatusCode) 'Admin could not remove the IPv6 CIDR entry.'

    Set-WhitelistPolicy -Entries @("$browserIP/32")
    Invoke-Compose exec --no-TTY caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
    $browserWhitelistState = Get-AdminInitial -CookieJar $adminJar
    $browserWhitelist = Invoke-AdminRequest -Path '/whitelist/add' -Method 'POST' -CookieJar $adminJar -CSRF $browserWhitelistState.csrf -Entry "$browserIP/32" -Name 'Browser test client'
    Assert-Equal '303' ([string][int]$browserWhitelist.StatusCode) 'Could not seed the browser test client in the admin whitelist.'

    $composeRows = Invoke-Compose ps --format json
    $mockRows = @($composeRows | ForEach-Object { $_ | ConvertFrom-Json })
    $mock = $mockRows | Where-Object { $_.Service -eq 'home-jellyfin' } | Select-Object -First 1
    if (-not $mock) {
        throw 'Compose did not report the home mock Jellyfin service.'
    }
    $inspection = (& docker inspect $mock.ID | ConvertFrom-Json)[0]
    if ($inspection.NetworkSettings.Ports.'8096/tcp') {
        throw 'Mock Jellyfin unexpectedly has a published host port.'
    }
    $wireguardContainer = $mockRows | Where-Object { $_.Service -eq 'wireguard' } | Select-Object -First 1
    $wireguardInspection = (& docker inspect $wireguardContainer.ID | ConvertFrom-Json)[0]
    if ($wireguardInspection.NetworkSettings.Ports.'51820/udp') { throw 'Test WireGuard UDP port unexpectedly has a host binding.' }
    $adminContainer = $mockRows | Where-Object { $_.Service -eq 'admin' } | Select-Object -First 1
    $adminInspection = (& docker inspect $adminContainer.ID | ConvertFrom-Json)[0]
    if ($adminInspection.NetworkSettings.Ports.'8080/tcp') { throw 'Admin unexpectedly has a published host port.' }
    & docker compose --project-name $projectName --file $composeFile exec --no-TTY admin sh -c 'test ! -e /opt/jellyfin-proxy/data/wireguard-client/windows.conf' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'One-time Windows config remained on the server after successful download.' }
    $serverConfigMode = & docker compose --project-name $projectName --file $composeFile exec --no-TTY wireguard stat -c '%a %u:%g' /etc/wireguard/wg0.conf
    Assert-Equal '600 0:0' ([string]$serverConfigMode).Trim() 'WireGuard server private config is not root-only.'
    & docker compose --project-name $projectName --file $composeFile exec --no-TTY admin sh -c 'test ! -e /opt/jellyfin-proxy/config/wireguard/server.conf && test ! -e /etc/wireguard/wg0.conf' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Admin container unexpectedly has access to the WireGuard server private key file.' }
    $hostMetricsContainer = $mockRows | Where-Object { $_.Service -eq 'hostmetrics' } | Select-Object -First 1
    $hostMetricsInspection = (& docker inspect $hostMetricsContainer.ID | ConvertFrom-Json)[0]
    if ($hostMetricsInspection.Config.User -ne '65532:65532') { throw 'Host metrics collector is not running as its unprivileged UID.' }
    if (-not $hostMetricsInspection.HostConfig.ReadonlyRootfs) { throw 'Host metrics collector root filesystem is writable.' }
    if ($hostMetricsInspection.HostConfig.CapDrop -notcontains 'ALL') { throw 'Host metrics collector retains Linux capabilities.' }
    if ($hostMetricsInspection.HostConfig.PidMode -or $hostMetricsInspection.HostConfig.NetworkMode -eq 'host') { throw 'Host metrics collector shares a host namespace.' }
    if ($hostMetricsInspection.NetworkSettings.Ports.'8181/tcp') { throw 'Host metrics endpoint unexpectedly has a published port.' }
    foreach ($target in @('/host/proc', '/host/sys', '/host/root')) {
        $mount = $hostMetricsInspection.Mounts | Where-Object { $_.Destination -eq $target } | Select-Object -First 1
        if (-not $mount -or $mount.RW) { throw "Host metrics mount $target is missing or writable." }
    }
    $caddyContainer = $mockRows | Where-Object { $_.Service -eq 'caddy' } | Select-Object -First 1
    $caddyInspection = (& docker inspect $caddyContainer.ID | ConvertFrom-Json)[0]
    if ($caddyInspection.NetworkSettings.Ports.'2019/tcp') { throw 'Caddy admin API unexpectedly has a published TCP port.' }

    Invoke-Compose restart hostmetrics
    Start-Sleep -Seconds 2

    # Rotate the active peer, confirm the old in-use client loses its tunnel,
    # then consume the replacement config once and use it to restore service.
    $rotationState = Get-AdminInitial -CookieJar $adminJar
    $rotation = Invoke-AdminRequest -Path '/wireguard/rotate' -Method 'POST' -CookieJar $adminJar -CSRF $rotationState.csrf
    Assert-Equal '303' ([string][int]$rotation.StatusCode) 'Administrator could not rotate and revoke the Windows peer.'
    $revokedProbe = Get-WireGuardHealth -TimeoutSeconds 2
    if ($revokedProbe.Healthy) { throw 'The previously active Windows peer remained able to reach Jellyfin after rotation.' }
    $replacementCsrf = (Get-AdminInitial -CookieJar $adminJar).csrf
    $replacementConfig = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar -CSRF $replacementCsrf
    Assert-Equal '200' ([string][int]$replacementConfig.StatusCode) 'Rotated Windows peer configuration was unavailable.'
    if ($replacementConfig.Body -notmatch '(?m)^PrivateKey = [A-Za-z0-9+/]{43}=$') { throw 'Rotated config did not contain a valid private key.' }
    $replacementPath = Join-Path $adminTempDir 'replacement-windows.conf'
    [System.IO.File]::WriteAllText($replacementPath, $replacementConfig.Body, [System.Text.UTF8Encoding]::new($false))
    $replacementAgain = Invoke-AdminRequest -Path '/wireguard/config' -Method 'POST' -CookieJar $adminJar -CSRF $replacementCsrf
    Assert-Equal '503' ([string][int]$replacementAgain.StatusCode) 'Rotated Windows configuration was not deleted after download.'
    $originalConfigPath = Join-Path $wireguardConfigDir 'windows.conf'
    & docker compose --project-name $projectName --file $composeFile cp $originalConfigPath home-peer:/tmp/windows.conf
    if ($LASTEXITCODE -ne 0) { throw 'Could not stage original peer config for interface shutdown.' }
    Invoke-Compose exec --no-TTY home-peer chmod 600 /tmp/windows.conf
    Invoke-Compose exec --no-TTY home-peer wg-quick down /tmp/windows.conf
    & docker compose --project-name $projectName --file $composeFile cp $replacementPath home-peer:/tmp/windows.conf
    if ($LASTEXITCODE -ne 0) { throw 'Could not copy rotated peer config to the integration client.' }
    Invoke-Compose exec --no-TTY home-peer chmod 600 /tmp/windows.conf
    Invoke-Compose exec --no-TTY home-peer wg-quick up /tmp/windows.conf
    $rotationRecoveryDeadline = (Get-Date).AddSeconds(15)
    $rotationRecovered = $false
    while ((Get-Date) -lt $rotationRecoveryDeadline) {
        $probe = Get-WireGuardHealth -TimeoutSeconds 2
        if ($probe.Healthy) { $rotationRecovered = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $rotationRecovered) { throw 'The rotated Windows peer could not restore Jellyfin reachability.' }
    & docker compose --project-name $projectName --file $composeFile exec --no-TTY admin sh -c 'test ! -e /opt/jellyfin-proxy/data/wireguard-client/windows.conf' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'A dependency container restart restored a consumed one-time Windows configuration.' }
    $rotatedHealth = Get-AdminInitial -CookieJar $adminJar
    foreach ($component in @('Windows peer', 'Jellyfin endpoint')) {
        $entry = @($rotatedHealth.components) | Where-Object name -eq $component | Select-Object -First 1
        Assert-Equal 'Healthy' $entry.state "$component did not recover after installing the rotated config."
    }
    Invoke-Compose --profile browser-tests run --rm browser-tests
    Invoke-Compose restart admin
    $postEnrollmentAdmin = Get-LocalResponse -Scheme 'https' -Port $HttpsPort -HostName 'admin.domain.test'
    Assert-Equal '200' ([string][int]$postEnrollmentAdmin.StatusCode) 'Admin service did not recover with active TOTP after restart.'

    Write-Host 'M6 and v1.1-v1.4 integration checks passed: browser authentication/TOTP, responsive admin navigation, security policy/SSE/history/ban UI, real Caddy admin enforcement and recovery, isolated Fail2ban/nftables IPv4/IPv6 enforcement, Jellyfin-route isolation, metrics/history, Caddy streaming, and WireGuard lifecycle/tunnel recovery.'
}
catch {
    $failureLogs = & docker compose --project-name $projectName --file $composeFile logs --no-color --tail 80 2>&1
    if ($LASTEXITCODE -eq 0 -and $failureLogs) {
        Write-Host "Integration service logs before cleanup:`n$($failureLogs -join "`n")"
    }
    throw
}
finally {
    try {
        Invoke-Compose down --remove-orphans --volumes --rmi local
    }
    finally {
        Remove-Item $policyFile -ErrorAction SilentlyContinue
        Remove-Item $credentialFile -ErrorAction SilentlyContinue
        if (Test-Path $wireguardConfigDir) { Remove-Item $wireguardConfigDir -Recurse -Force -ErrorAction SilentlyContinue }
        if ($adminTempDir) { Remove-Item $adminTempDir -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Item Env:HTTP_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:TEST_SUBNET -ErrorAction SilentlyContinue
        Remove-Item Env:TRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Remove-Item Env:UNTRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Remove-Item Env:BROWSER_TEST_IP -ErrorAction SilentlyContinue
        Remove-Item Env:WIREGUARD_IP -ErrorAction SilentlyContinue
        Remove-Item Env:SECURITYD_IP -ErrorAction SilentlyContinue
        Remove-Item Env:ADMIN_IP -ErrorAction SilentlyContinue
        Remove-Item Env:HOSTMETRICS_IP -ErrorAction SilentlyContinue
        Remove-Item Env:HOME_PEER_IP -ErrorAction SilentlyContinue
        Remove-Item Env:SECURITY_TEST_IMAGE -ErrorAction SilentlyContinue
        Remove-Item Env:BROWSER_SNAPSHOT_MODE -ErrorAction SilentlyContinue
        & docker image rm $securityTestImage $securityBaseImage 2>&1 | Out-Null
        Pop-Location
    }
}
