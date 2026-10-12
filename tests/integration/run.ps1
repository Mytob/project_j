[CmdletBinding()]
param(
    [int]$HttpPort = 18080,
    [int]$HttpsPort = 18443
)

$ErrorActionPreference = 'Stop'
$projectName = "jellyfin-proxy-m3-$PID"
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
$policyFile = Join-Path $PSScriptRoot 'whitelist.caddy.generated'
$credentialFile = Join-Path $PSScriptRoot 'admin-credential.generated.json'
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
    for ($attempt = 1; $attempt -le 10; $attempt++) {
        $output = & curl.exe --noproxy '*' --silent --show-error --insecure --resolve $resolve --write-out "`n%{http_code}" $uri
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
        $arguments = @('run', '--rm', '-v', "${repoPath}:/src", '-w', '/src', 'golang:1.25.2-alpine3.22', 'go', 'run', './tests/integration/policygen')
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
    if (Get-Command go -ErrorAction SilentlyContinue) {
        & go run ./tests/integration/credentialgen --output $credentialFile --password $password
    }
    else {
        $repoPath = $repoRoot.Replace('\', '/')
        & docker run --rm -v "${repoPath}:/src" -w /src golang:1.25.2-alpine3.22 go run ./tests/integration/credentialgen --output ./tests/integration/admin-credential.generated.json --password $password
    }
    if ($LASTEXITCODE -ne 0) { throw "Test credential generation failed with exit code $LASTEXITCODE" }
    # Windows bind mounts may map the generated owner-only file to an unrelated
    # container UID. This fixture contains only the disposable integration password.
    $repoPath = $repoRoot.Replace('\', '/')
    & docker run --rm -v "${repoPath}:/src" alpine:3.22 chmod 644 /src/tests/integration/admin-credential.generated.json
    if ($LASTEXITCODE -ne 0) { throw "Test credential fixture permissions could not be set (exit $LASTEXITCODE)" }
}

function Invoke-AdminRequest([string]$Path, [string]$Method, [string]$CookieJar, [string]$CSRF = '', [string]$Password = '') {
    $uri = "https://admin.domain.test:${HttpsPort}${Path}"
    $resolve = "admin.domain.test:${HttpsPort}:127.0.0.1"
    $headersPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.headers')
    $bodyPath = Join-Path $adminTempDir ([guid]::NewGuid().ToString() + '.body')
    $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--insecure', '--resolve', $resolve, '--cookie', $CookieJar, '--cookie-jar', $CookieJar, '--dump-header', $headersPath, '--output', $bodyPath)
    if ($Method -eq 'POST') {
        $curlArgs += @('--request', 'POST', '--data-urlencode', "csrf=$CSRF")
        if ($Path -eq '/login') { $curlArgs += @('--data-urlencode', "password=$Password") }
    }
    $curlArgs += @('--write-out', '%{http_code}', $uri)
    $status = & curl.exe @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "curl failed for $uri with exit code $LASTEXITCODE" }
    $code = 0
    if (-not [int]::TryParse([string]$status, [ref]$code)) { throw "curl returned an invalid status for $uri" }
    [pscustomobject]@{ StatusCode = $code; Body = [System.IO.File]::ReadAllText($bodyPath); Headers = [System.IO.File]::ReadAllText($headersPath) }
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
    $script:adminTempDir = Join-Path $env:TEMP "jellyfin-proxy-admin-test-$PID"
    New-Item -ItemType Directory -Path $adminTempDir -Force | Out-Null
    New-TestCredential

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
    $adminJar = Join-Path $adminTempDir 'admin.cookies'
    $unauthorized = Invoke-AdminRequest -Path '/dashboard' -Method 'GET' -CookieJar $adminJar
    if ($unauthorized.StatusCode -eq 502) {
        $adminLogs = & docker compose --project-name $projectName --file $composeFile logs admin
        throw "Admin service returned 502. Container logs:`n$($adminLogs -join "`n")"
    }
    Assert-Equal '303' ([string][int]$unauthorized.StatusCode) 'Unauthenticated admin dashboard did not redirect to sign-in.'
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
    $logoutCsrfMatch = [regex]::Match($dashboard.Body, 'name="csrf" value="([^"]+)"')
    if (-not $logoutCsrfMatch.Success) { throw 'Admin dashboard did not include a logout CSRF token.' }
    $logout = Invoke-AdminRequest -Path '/logout' -Method 'POST' -CookieJar $adminJar -CSRF $logoutCsrfMatch.Groups[1].Value
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

    Write-Host 'M3 integration checks passed: M1 routing, M2 access control, admin authentication, secure sessions, CSRF, logout, throttling, and no mock exposure.'
}
finally {
    try {
        Invoke-Compose down --remove-orphans --volumes --rmi local
    }
    finally {
        Remove-Item $policyFile -ErrorAction SilentlyContinue
        Remove-Item $credentialFile -ErrorAction SilentlyContinue
        if ($adminTempDir) { Remove-Item $adminTempDir -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Item Env:HTTP_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:HTTPS_PORT -ErrorAction SilentlyContinue
        Remove-Item Env:TEST_SUBNET -ErrorAction SilentlyContinue
        Remove-Item Env:TRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Remove-Item Env:UNTRUSTED_CLIENT_IP -ErrorAction SilentlyContinue
        Pop-Location
    }
}
