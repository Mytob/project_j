# Testing

## Strategy

Tests are layered: focused Go package tests, then targeted integration tests,
then the complete release gate. A mandatory test is not skipped silently. A
test requiring a Linux host, kernel capability, or public DNS must be listed as
a blocker when unavailable and must not be represented as proven by simulation.

## Local environment

M1 Windows checks use PowerShell 7, Go 1.24+, Docker Desktop's Linux engine,
and Docker Compose v2. WSL2 is intended for Linux-specific packaging and
network checks. Do not run the local M1 Compose project as a public service.

## Commands

```powershell
go test ./...
./build.ps1 test
```

`build.ps1 test` runs Go unit tests and the M1 Compose integration runner. The
runner builds a Go mock image, starts a uniquely named temporary Compose
project, verifies routing, then removes only that project's containers and
network. It publishes test Caddy ports on loopback only.

The full command is `./build.ps1 release`; it must be expanded to cover each
mandatory release check before M10 can pass.

## Test coverage matrix

| Area | Planned automated coverage | Status |
| --- | --- | --- |
| M1 Caddy HTTP/HTTPS, site, mock forwarding, unpublished mock port | Compose integration | Not run yet |
| Whitelist parsing and enforcement | Unit + Caddy integration, empty default deny, spoofed headers | Not implemented |
| Authentication and sessions | Unit + HTTP integration, expiry, logout, CSRF, attempts, persistence | Not implemented |
| Live Caddy updates | Unix socket integration, invalid update and rollback, concurrency, restart persistence | Not implemented |
| WireGuard | Encrypted tunnel from mock peer to mock Jellyfin; recovery | Not implemented; Linux kernel capability required |
| Windows client config | Key/config validation, repeat authenticated downloads, permissions | Not implemented |
| Package | Extract/load images in clean Docker daemon without registry pulls | Not implemented |
| Installer/updater | Fresh install, preservation, failure rollback, SSH/firewall preservation, scoped cleanup | Not implemented; Ubuntu host checks required |
| Full release | All prior gates, package compatibility, restart and unrelated Docker resource checks | Not implemented |

## Host-specific limitations

Local Caddy TLS verifies hostname routing but does not prove public ACME
certificate issuance. Docker simulation does not prove Ubuntu host firewall,
public ingress, or VPS routing. WireGuard requires tunnel tests on a host with
the required kernel support. Windows Firewall rules and actual Windows
WireGuard client import need host verification. Release readiness must report
these limits explicitly and use VPS preflight checks.

## Results log

No automated results have been recorded in the documentation commit yet. Add
the actual command, result, environment, and blocker after implementation tests
run.
