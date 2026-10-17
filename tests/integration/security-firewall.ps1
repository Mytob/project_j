$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$network = "jp-v14-firewall-$suffix"
$security = "jp-v14-securityd-$suffix"
$client = "jp-v14-client-$suffix"
$otherClient = "jp-v14-other-$suffix"
$image = "jellyfin-proxy/security:firewall-test-$suffix"
$curlImage = 'curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777'

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker operation failed: docker $($Arguments -join ' ')" }
}

function Get-ContainerIP([string]$Name) {
    $value = & docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $Name
    if ($LASTEXITCODE -ne 0 -or -not $value) { throw "Could not get the isolated container IP for $Name." }
    ([string]$value).Trim()
}

function Get-HttpStatus([string]$ClientName, [string]$ServerIP) {
    $output = & docker exec $ClientName curl --noproxy '*' --silent --show-error --connect-timeout 2 --max-time 3 --output /dev/null --write-out '%{http_code}' "http://${ServerIP}:22/" 2>&1
    $exitCode = $LASTEXITCODE
    [pscustomobject]@{ ExitCode = $exitCode; Status = [string]($output -join '').Trim() }
}

try {
    foreach ($name in @($security, $client, $otherClient)) {
        $existing = & docker container ls -a --filter "name=^/$name$" --format '{{.ID}}'
        if ($existing) { throw "Refusing to replace existing test container $name." }
    }
    Invoke-Docker @('build', '--file', (Join-Path $repoRoot 'deploy/security/Dockerfile'), '--tag', $image, $repoRoot)
    Invoke-Docker @('network', 'create', '--internal', $network)
    Invoke-Docker @('run', '--detach', '--name', $security, '--network', $network, '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges:true', '--entrypoint', '/bin/sh', $image, '-c', 'while true; do sleep 1; done')
    Invoke-Docker @('exec', $security, 'nft', 'add', 'table', 'inet', 'jp_unrelated_test')
    Invoke-Docker @('exec', $security, 'fail2ban-server', '-x', '--socket', '/tmp/fail2ban.sock', '--pidfile', '/tmp/fail2ban.pid', '--logtarget=stdout', '--loglevel=INFO', 'start')

    $pinged = $false
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock ping 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $pinged = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $pinged) {
        $logs = & docker logs --tail 100 $security 2>&1
        throw "Fail2ban did not become ready in the isolated namespace: $($logs -join "`n")"
    }
    $status = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock status
    if ($LASTEXITCODE -ne 0 -or ([string]($status -join "`n")).Contains('sshd')) { throw 'Fail2ban loaded an extra/default SSH jail.' }
    foreach ($jail in @('jp-ssh', 'jp-admin')) {
        $jailStatus = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock status $jail
        if ($LASTEXITCODE -ne 0) { throw "Fail2ban did not start the $jail jail." }
    }
    $startupRules = & docker exec $security nft list chain inet jp_fail2ban jp_ssh_input
    if ($LASTEXITCODE -ne 0 -or ([string]($startupRules -join "`n")) -notmatch 'tcp dport 22.*drop') {
        $action = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock get jp-ssh actions
        $startMode = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock get jp-ssh action nftables-multiport actionstart_on_demand
        $startCommand = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock get jp-ssh action nftables-multiport actionstart
        throw "Fail2ban did not install its TCP/22 SSH enforcement chain when the jail started. Actions=$($action -join ','); actionstart_on_demand=$($startMode -join ','); actionstart=$($startCommand -join ' ')"
    }

    Invoke-Docker @('run', '--detach', '--name', $client, '--network', $network, '--entrypoint', '/bin/sh', $curlImage, '-c', 'sleep 600')
    Invoke-Docker @('run', '--detach', '--name', $otherClient, '--network', $network, '--entrypoint', '/bin/sh', $curlImage, '-c', 'sleep 600')
    $securityIP = Get-ContainerIP $security
    $clientIP = Get-ContainerIP $client
    $otherIP = Get-ContainerIP $otherClient
    Invoke-Docker @('exec', '--detach', $security, 'python3', '-m', 'http.server', '22', '--bind', '0.0.0.0', '--directory', '/tmp')

    $deadline = (Get-Date).AddSeconds(15)
    $available = $false
    while ((Get-Date) -lt $deadline) {
        $response = Get-HttpStatus $client $securityIP
        if ($response.ExitCode -eq 0 -and $response.Status -eq '200') { $available = $true; break }
        Start-Sleep -Milliseconds 300
    }
    if (-not $available) { throw 'The isolated SSH test port was not reachable before installing a ban.' }

    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-ssh', 'bantime', '60')
    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-ssh', 'banip', $clientIP)
    $blocked = Get-HttpStatus $client $securityIP
    if ($blocked.ExitCode -eq 0) { throw 'The SSH nftables ban did not block the banned source address.' }
    $unrelated = & docker exec $security nft list table inet jp_unrelated_test
    if ($LASTEXITCODE -ne 0 -or -not $unrelated) { throw 'Fail2ban changed or removed an unrelated nftables table.' }
    $otherResponse = Get-HttpStatus $otherClient $securityIP
    if ($otherResponse.ExitCode -ne 0 -or $otherResponse.Status -ne '200') { throw 'The SSH ban affected a different source IP.' }

    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-ssh', 'unbanip', $clientIP)
    $restored = Get-HttpStatus $client $securityIP
    if ($restored.ExitCode -ne 0 -or $restored.Status -ne '200') { throw 'Unbanning the SSH source did not restore its connection.' }

    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-ssh', 'banip', '2001:db8::10')
    $ipv6Set = & docker exec $security nft list set inet jp_fail2ban addr6-set-jp-ssh
    if ($LASTEXITCODE -ne 0 -or ([string]($ipv6Set -join "`n")) -notmatch '2001:db8::10') { throw 'Fail2ban did not install an IPv6 exact-address rule.' }
    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-ssh', 'unbanip', '2001:db8::10')

    $sshRulesBefore = & docker exec $security nft list table inet jp_fail2ban
    Invoke-Docker @('exec', $security, 'fail2ban-client', '--socket', '/tmp/fail2ban.sock', 'set', 'jp-admin', 'banip', $clientIP)
    $sshRulesAfter = & docker exec $security nft list table inet jp_fail2ban
    if (($sshRulesAfter -join "`n") -cne ($sshRulesBefore -join "`n")) { throw 'The admin jail modified the SSH firewall rules.' }
    $adminBan = & docker exec $security fail2ban-client --socket /tmp/fail2ban.sock get jp-admin banned $clientIP
    if ($LASTEXITCODE -ne 0 -or ([string]($adminBan -join '').Trim() -ne '1')) { throw 'Fail2ban did not retain the admin-jail ban state.' }

    Write-Host 'Isolated Fail2ban enforcement passed: exactly two jails, TCP/22 IPv4/IPv6 blocking, per-IP scope, unban recovery, and unrelated nftables preservation.'
}
finally {
    & docker rm --force $client $otherClient $security 2>&1 | Out-Null
    & docker network rm $network 2>&1 | Out-Null
    & docker image rm $image 2>&1 | Out-Null
}
