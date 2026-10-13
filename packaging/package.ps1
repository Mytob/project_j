[CmdletBinding()]
param(
    [string]$Version = '1.0.0-dev',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    throw "Version '$Version' is not a supported semantic version."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot 'dist' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$outputRoot = (Resolve-Path $OutputDirectory).Path
$workDirectory = Join-Path $outputRoot ".package-$PID"
$packageDirectory = Join-Path $workDirectory "jellyfin-proxy-$Version-linux-amd64"
$archivePath = Join-Path $outputRoot "jellyfin-proxy-$Version-linux-amd64.tar.gz"
$daemonName = "jellyfin-proxy-package-check-$PID"
$imageReferences = @(
    "jellyfin-proxy/admin:$Version",
    "jellyfin-proxy/wireguard:$Version",
    'caddy:2.10.2-alpine',
    'alpine:3.22'
)

function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-ImageID([string]$Reference) {
    $id = & docker image inspect --format '{{.Id}}' $Reference
    if ($LASTEXITCODE -ne 0 -or -not $id) { throw "Could not inspect packaged image $Reference" }
    [string]$id
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

try {
    if (Get-Command tar.exe -ErrorAction SilentlyContinue) { $tar = 'tar.exe' } else { throw 'Windows tar.exe is required to create and inspect the release archive.' }
    if (Test-Path $workDirectory) { throw "Package work path already exists: $workDirectory" }
    New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $packageDirectory 'bin') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $packageDirectory 'config') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $packageDirectory 'site') -Force | Out-Null

    $repoMount = $repoRoot.Replace('\', '/')
    $binDirectory = Join-Path $packageDirectory 'bin'
    $binMount = $binDirectory.Replace('\', '/')
    $workMount = $workDirectory.Replace('\', '/')
    Invoke-Checked 'docker' @('run', '--rm', '-v', "${repoMount}:/src", '-v', "${binMount}:/out", '-w', '/src', '-e', 'CGO_ENABLED=0', '-e', 'GOOS=linux', '-e', 'GOARCH=amd64', 'golang:1.25.2-alpine3.22', 'go', 'build', '-trimpath', '-ldflags=-s -w', '-o', '/out/admin-linux-amd64', './cmd/admin')
    Invoke-Checked 'docker' @('run', '--rm', '-v', "${repoMount}:/src", '-v', "${binMount}:/out", '-w', '/src', '-e', 'CGO_ENABLED=0', '-e', 'GOOS=linux', '-e', 'GOARCH=amd64', 'golang:1.25.2-alpine3.22', 'go', 'build', '-trimpath', '-ldflags=-s -w', '-o', '/out/proxyctl-linux-amd64', './cmd/proxyctl')
    Invoke-Checked 'docker' @('run', '--rm', '-v', "${repoMount}:/src", '-v', "${workMount}:/out", '-w', '/src', '-e', 'CGO_ENABLED=0', '-e', 'GOOS=linux', '-e', 'GOARCH=amd64', 'golang:1.25.2-alpine3.22', 'go', 'build', '-trimpath', '-ldflags=-s -w', '-o', '/out/installcheck-linux-amd64', './tests/deployment/installcheck')

    $adminImage = $imageReferences[0]
    $wireguardImage = $imageReferences[1]
    Invoke-Checked 'docker' @('build', '--file', 'deploy/admin/Dockerfile', '--tag', $adminImage, '.')
    Invoke-Checked 'docker' @('build', '--file', 'deploy/wireguard/Dockerfile', '--tag', $wireguardImage, '.')
    Invoke-Checked 'docker' @('pull', $imageReferences[2])
    Invoke-Checked 'docker' @('pull', $imageReferences[3])

    Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy/compose.yaml') -Destination (Join-Path $packageDirectory 'compose.yaml')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy/PACKAGE-ENV.example') -Destination (Join-Path $packageDirectory '.env.example')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy/caddy/Caddyfile') -Destination (Join-Path $packageDirectory 'config/Caddyfile')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy/caddy/whitelist.default.caddy') -Destination (Join-Path $packageDirectory 'config/whitelist.caddy')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'deploy/site/index.html') -Destination (Join-Path $packageDirectory 'site/index.html')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs/DEPLOYMENT.md') -Destination (Join-Path $packageDirectory 'DEPLOYMENT.md')
    $imagesArchivePath = Join-Path $packageDirectory 'images.tar'
    Invoke-Checked 'docker' (@('image', 'save', '--output', $imagesArchivePath) + $imageReferences)

    # Docker may save a platform-specific image config while the local tag points
    # to a BuildKit manifest list. Use the config digest from the shipped archive
    # so the manifest describes the exact image that a clean daemon will load.
    $savedImagesJson = & $tar @('-xOf', $imagesArchivePath, 'manifest.json')
    if ($LASTEXITCODE -ne 0 -or -not $savedImagesJson) { throw 'Could not inspect the saved Docker image manifest.' }
    $savedImages = ($savedImagesJson -join "`n") | ConvertFrom-Json

    $imageManifest = @(
        foreach ($reference in $imageReferences) {
            $matches = @($savedImages | Where-Object { $_.RepoTags -contains $reference })
            if ($matches.Count -ne 1) { throw "Docker image archive does not contain exactly one entry for $reference" }
            $configID = [System.IO.Path]::GetFileNameWithoutExtension([string]$matches[0].Config)
            if ($configID -notmatch '^[a-f0-9]{64}$') { throw "Docker image archive has an invalid config digest for $reference" }
            [ordered]@{ reference = $reference; image_id = "sha256:$configID" }
        }
    )
    $relativeFiles = @('images.tar', 'bin/admin-linux-amd64', 'bin/proxyctl-linux-amd64', 'compose.yaml', '.env.example', 'config/Caddyfile', 'config/whitelist.caddy', 'site/index.html', 'DEPLOYMENT.md')
    $fileManifest = @(
        foreach ($relative in $relativeFiles) {
            $path = Join-Path $packageDirectory $relative
            [ordered]@{ path = $relative; size_bytes = (Get-Item -LiteralPath $path).Length; sha256 = Get-Sha256 $path }
        }
    )
    $manifest = [ordered]@{
        schema_version = 1
        version = $Version
        platform = 'linux/amd64'
        images = $imageManifest
        files = $fileManifest
    }
    $manifestPath = Join-Path $packageDirectory 'manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8

    $daemonMatches = & docker ps -a --filter "name=^${daemonName}$" --format '{{.Names}}'
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect Docker containers before clean-daemon package validation.' }
    if ($daemonMatches) { throw "Package validation container name already exists: $daemonName" }

    $dindImage = 'docker:27.5-dind'
    Invoke-Checked 'docker' @('pull', $dindImage)
    $imagesMount = (Join-Path $packageDirectory 'images.tar').Replace('\', '/')
    $distMount = $outputRoot.Replace('\', '/')
    Invoke-Checked 'docker' @('run', '--privileged', '--detach', '--name', $daemonName, '--network', 'none', '--env', 'DOCKER_TLS_CERTDIR=', '-v', "${imagesMount}:/package/images.tar:ro", '-v', "${distMount}:/package/dist:ro", $dindImage)

    $daemonReady = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        & docker exec $daemonName docker info *> $null
        if ($LASTEXITCODE -eq 0) { $daemonReady = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $daemonReady) {
        $logs = & docker logs $daemonName 2>&1
        throw "Isolated Docker daemon did not become ready:`n$($logs -join "`n")"
    }
    Invoke-Checked 'docker' @('exec', $daemonName, 'docker', 'image', 'load', '--input', '/package/images.tar')
    foreach ($reference in $imageReferences) {
        $loaded = & docker exec $daemonName docker image inspect --format '{{.Id}}' $reference
        if ($LASTEXITCODE -ne 0 -or -not $loaded) { throw "Clean Docker daemon did not load packaged image $reference" }
    }

    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
    Invoke-Checked $tar @('-czf', $archivePath, '-C', $packageDirectory, '.')
    $archiveList = @(& $tar @('-tzf', $archivePath))
    if ($LASTEXITCODE -ne 0) { throw 'Could not list the built release archive.' }
    $normalizedEntries = @($archiveList | ForEach-Object { ([string]$_).Replace('./', '').TrimEnd('/') })
    foreach ($relative in @('manifest.json', 'images.tar', 'bin/admin-linux-amd64', 'bin/proxyctl-linux-amd64', 'compose.yaml', 'config/Caddyfile', 'config/whitelist.caddy', 'site/index.html')) {
        if ($normalizedEntries -notcontains $relative) { throw "Release archive is missing $relative" }
    }
    foreach ($secretName in @('server.conf', 'windows.conf', 'admin.json', 'totp.key', 'totp-state.json')) {
        if ($normalizedEntries -match "(^|/)$([regex]::Escape($secretName))$") { throw "Release archive unexpectedly contains sensitive runtime file $secretName" }
    }

    $verifyDirectory = Join-Path $workDirectory 'verify'
    New-Item -ItemType Directory -Path $verifyDirectory | Out-Null
    Invoke-Checked $tar @('-xzf', $archivePath, '-C', $verifyDirectory)
    $verifiedManifest = Get-Content -LiteralPath (Join-Path $verifyDirectory 'manifest.json') -Raw | ConvertFrom-Json
    if ($verifiedManifest.schema_version -ne 1 -or $verifiedManifest.version -ne $Version -or $verifiedManifest.platform -ne 'linux/amd64') {
        throw 'Packaged manifest has an unexpected schema, version, or platform.'
    }
    foreach ($file in $verifiedManifest.files) {
        $path = Join-Path $verifyDirectory $file.path
        $resolved = (Resolve-Path -LiteralPath $path).Path
        $verifyRoot = (Resolve-Path -LiteralPath $verifyDirectory).Path.TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($verifyRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw "Manifest file escaped the extracted package directory: $($file.path)" }
        if ((Get-Item -LiteralPath $path).Length -ne $file.size_bytes -or (Get-Sha256 $path) -ne $file.sha256) {
            throw "Packaged file failed manifest verification: $($file.path)"
        }
    }
    foreach ($image in $verifiedManifest.images) {
        $loadedID = & docker exec $daemonName docker image inspect --format '{{.Id}}' $image.reference
        if ($LASTEXITCODE -ne 0 -or [string]$loadedID -ne [string]$image.image_id) {
            throw "Image identity in the clean daemon does not match manifest for $($image.reference)"
        }
    }

    Invoke-Checked 'docker' @('exec', $daemonName, "/package/dist/.package-$PID/installcheck-linux-amd64", "/package/dist/jellyfin-proxy-$Version-linux-amd64.tar.gz")

    Copy-Item -LiteralPath (Join-Path $packageDirectory 'bin/proxyctl-linux-amd64') -Destination (Join-Path $outputRoot 'proxyctl-linux-amd64') -Force

    Write-Host "Package validation passed: $archivePath (version $Version, $($imageReferences.Count) images loaded into an isolated daemon without registry access)."
}
finally {
    $daemonMatches = & docker ps -a --filter "name=^${daemonName}$" --format '{{.Names}}' 2>$null
    if ($daemonMatches -contains $daemonName) { & docker rm --force $daemonName *> $null }
    if (Test-Path -LiteralPath $workDirectory) {
        $resolvedWork = (Resolve-Path -LiteralPath $workDirectory).Path
        $outputPrefix = $outputRoot.TrimEnd('\') + '\'
        if (-not $resolvedWork.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove package work directory outside dist: $resolvedWork"
        }
        Remove-Item -LiteralPath $resolvedWork -Recurse -Force -ErrorAction SilentlyContinue
    }
}
