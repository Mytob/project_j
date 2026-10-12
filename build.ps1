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

throw 'The full release gate is not implemented yet; see docs/ROADMAP.md. Release checks are not skipped.'
