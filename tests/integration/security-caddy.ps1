$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$repoMount = $repoRoot.Replace('\', '/')
$caddyfile = (Resolve-Path (Join-Path $PSScriptRoot 'Caddyfile.security')).Path.Replace('\', '/')
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 10)
$network = "jp-v14-caddy-$suffix"
$volume = "jp-v14-caddy-socket-$suffix"
$container = "jp-v14-caddy-probe-$suffix"
$image = "jellyfin-proxy/caddy:security-test-$suffix"

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker operation failed: docker $($Arguments -join ' ')" }
}

try {
    $existing = & docker container ls -a --filter "name=^/$container$" --format '{{.ID}}'
    if ($existing) { throw "Refusing to replace existing test container $container." }
    Invoke-Docker @('build', '--file', (Join-Path $repoRoot 'deploy/caddy/Dockerfile'), '--tag', $image, $repoRoot)
    Invoke-Docker @('network', 'create', '--internal', $network)
    Invoke-Docker @('volume', 'create', $volume)
    Invoke-Docker @('run', '--rm', '--volume', "${volume}:/run/caddy-security", 'alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6', 'sh', '-c', 'chown 1000:1000 /run/caddy-security && chmod 2770 /run/caddy-security')
    Invoke-Docker @('run', '--detach', '--name', $container, '--network', $network, '--volume', "${volume}:/run/caddy-security", '--volume', "${caddyfile}:/etc/caddy/Caddyfile:ro", $image, 'caddy', 'run', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile')
    $deadline = (Get-Date).AddSeconds(30)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        $output = & docker run --rm --network "container:$container" --volumes-from $container --volume "${repoMount}:/src" --workdir /src golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d go run ./tests/integration/securityprobe --socket /run/caddy-security/control.sock --origin http://127.0.0.1:8080
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "Caddy security module integration did not become ready. Last output: $($output -join "`n")" }
    Write-Host ($output -join "`n")
}
finally {
    & docker rm --force $container 2>&1 | Out-Null
    & docker network rm $network 2>&1 | Out-Null
    & docker volume rm $volume 2>&1 | Out-Null
    & docker image rm $image 2>&1 | Out-Null
}
