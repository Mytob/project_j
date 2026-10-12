[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('test', 'package', 'release')]
    [string]$Target = 'test',
    [string]$Version = '1.0.0-dev'
)

$ErrorActionPreference = 'Stop'

function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

if ($Target -eq 'release') {
    $outputDirectory = Join-Path $PSScriptRoot 'dist'
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $reportPath = Join-Path $outputDirectory "release-validation-$Version.json"
    $checks = @(
        [ordered]@{ id = 'go-tests'; status = 'not_run'; evidence = 'Go unit tests and compilation.' }
        [ordered]@{ id = 'm1-m6-integration'; status = 'not_run'; evidence = 'Caddy routes, auth, whitelist, WireGuard tunnel, restart and recovery.' }
        [ordered]@{ id = 'm7-m9-package'; status = 'not_run'; evidence = 'Release archive, offline image loading, install, firewall, update, rollback, retention, and password reset.' }
    )
    $hostChecks = [ordered]@{
        status = 'blocked'
        reason = 'These checks require operator-controlled production hosts and are not simulated by this runner.'
        preflight = @(
            [ordered]@{ check = 'Ubuntu 26.04 LTS, x86_64, root privileges'; implemented = 'proxyctl install validates OS, release, architecture, codename, and effective UID before deployment.' }
            [ordered]@{ check = 'Docker Engine and Compose'; implemented = 'proxyctl install checks daemon and Compose availability and offers the official Ubuntu APT installation path when missing.' }
            [ordered]@{ check = 'Public DNS'; implemented = 'proxyctl install resolves the base, admin, and access hostnames and asks the operator to confirm their VPS target.' }
            [ordered]@{ check = 'Windows WireGuard client and Firewall'; implemented = 'Installation and firewall guidance is documented; actual native client import and firewall behavior require Windows host verification.' }
        )
        checks = @(
            [ordered]@{ id = 'ubuntu-vps-kernel-wireguard'; status = 'blocked'; detail = 'Ubuntu 26.04 VPS kernel and WireGuard runtime require an actual target VPS.' }
            [ordered]@{ id = 'public-acme-provider-firewall'; status = 'blocked'; detail = 'Public DNS target, ACME issuance, and provider firewall ingress require production network access.' }
            [ordered]@{ id = 'native-windows-client-firewall'; status = 'blocked'; detail = 'Native Windows WireGuard client import and Windows Firewall behavior require a Windows client host.' }
        )
    }
    $report = [ordered]@{
        schema_version = 1
        version = $Version
        generated_at_utc = [DateTime]::UtcNow.ToString('o')
        local_gate = 'running'
        release_readiness = 'blocked_host_checks_pending'
        checks = $checks
        host_specific_checks = $hostChecks
    }
    $failure = $null
    try {
        $checks[0].status = 'running'
        $goCommand = Get-Command go -ErrorAction SilentlyContinue
        if ($goCommand) {
            Invoke-Checked 'go' @('test', './...')
        }
        else {
            if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
                throw 'Go 1.24+ or Docker is required to run Go tests.'
            }
            $repoPath = (Resolve-Path $PSScriptRoot).Path.Replace('\', '/')
            Invoke-Checked 'docker' @('run', '--rm', '-v', "${repoPath}:/src", '-w', '/src', 'golang:1.25.2-alpine3.22', 'go', 'test', './...')
        }
        $checks[0].status = 'passed'

        $checks[1].status = 'running'
        Invoke-Checked 'pwsh' @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'tests/integration/run.ps1'))
        $checks[1].status = 'passed'

        $checks[2].status = 'running'
        Invoke-Checked 'pwsh' @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'packaging/package.ps1'), '-Version', $Version)
        $checks[2].status = 'passed'
        $report.local_gate = 'passed'
    }
    catch {
        $failure = $_.Exception
        $report.local_gate = 'failed'
        foreach ($check in $checks) {
            if ($check.status -eq 'running') { $check.status = 'failed' }
            elseif ($check.status -eq 'not_run') { $check.status = 'not_run_after_failure' }
        }
        $hostChecks.reason = 'The local gate failed before production-host checks could be considered.'
    }
    finally {
        $report.generated_at_utc = [DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8NoBOM
    }
    Write-Host "Release validation report: $reportPath"
    if ($failure) {
        Write-Error "M10 local release validation failed: $($failure.Message)"
        exit 1
    }
    Write-Host 'M10 local release validation passed: Go, M1–M6 integration, and M7–M9 offline package gates all passed.'
    Write-Warning 'Release readiness is BLOCKED pending actual Ubuntu VPS/provider-firewall and native Windows client checks. See the JSON report and docs/DEPLOYMENT.md.'
    exit 0
}

$goCommand = Get-Command go -ErrorAction SilentlyContinue
if ($goCommand) {
    Invoke-Checked 'go' @('test', './...')
}
else {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Go 1.24+ or Docker is required to run Go tests.'
    }
    $repoPath = (Resolve-Path $PSScriptRoot).Path.Replace('\', '/')
    Invoke-Checked 'docker' @('run', '--rm', '-v', "${repoPath}:/src", '-w', '/src', 'golang:1.25.2-alpine3.22', 'go', 'test', './...')
}

if ($Target -eq 'test') {
    Invoke-Checked 'pwsh' @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'tests/integration/run.ps1'))
    exit 0
}

if ($Target -eq 'package') {
    Invoke-Checked 'pwsh' @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'tests/integration/run.ps1'))
    Invoke-Checked 'pwsh' @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'packaging/package.ps1'), '-Version', $Version)
    exit 0
}

throw "Unknown build target '$Target'."
