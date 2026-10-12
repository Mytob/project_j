# Jellyfin Proxy

Jellyfin Proxy is a self-hosted, default-deny gateway for one Jellyfin server
on a Windows PC. The planned 1.0 deployment uses Caddy and WireGuard containers
on an Ubuntu VPS, with a small Go application for administration and a native
Linux `proxyctl` installer.

The repository has completed Milestones 1–6. Its local test environment
routes a static site and simulated Jellyfin through Caddy, with an IPv4/IPv6/
CIDR default-deny allowlist for the access hostname. The admin hostname now
serves a password-protected Go sign-in and session dashboard with persistent
whitelist management and live Caddy updates through a private Unix socket.
The integration environment also verifies real WireGuard traffic between a
server peer and a mock home Jellyfin endpoint, including outage and recovery.
The admin dashboard provides an authenticated download of the retained Windows
WireGuard config. Production provisioning, installation, and release packaging
remain roadmap work.

## Supported platforms

- Development: Windows 11 x64 with PowerShell 7, Docker Desktop, and Go 1.24+
  (WSL2 is intended for Linux-specific checks when available).
- Production target: Ubuntu 26.04 LTS x64 with Docker Engine and Docker Compose.
- Windows Jellyfin host: Windows 11 x64 with the official WireGuard client.

## Architecture

The intended request path is Internet → Ubuntu VPS → WireGuard tunnel →
Windows Jellyfin. Caddy serves the base-domain site, terminates HTTPS for all
three hostnames, and routes the access hostname to Jellyfin over the tunnel.
The admin hostname serves a password-protected Go application. The access
hostname will enforce a persisted IP/CIDR whitelist with default-deny behaviour.

See [architecture](docs/ARCHITECTURE.md) for trust boundaries and deployment
details, and [roadmap](docs/ROADMAP.md) for verified implementation status.

## Development prerequisites

- PowerShell 7
- Go 1.24 or later
- Docker Desktop with the Linux container engine running
- Docker Compose v2

WSL2 is useful for Ubuntu-specific packaging and host checks. The current
Docker Desktop Linux engine supports the WireGuard integration test.

## Build and test

Run Go unit tests:

```powershell
go test ./...
```

Run Go unit tests and the M1–M6 Caddy/admin/WireGuard integration checks
(builds local test images, starts a temporary Compose project, then removes
that project):

```powershell
./build.ps1 test
```

The full release command will be enabled after its required gates exist:

```powershell
./build.ps1 release
```

See [testing](docs/TESTING.md) for the test matrix and current limitations.

## Installation and updates

Production installation is not implemented yet. Once complete, `proxyctl`
will provide guided installation, updates, password reset, and rollback. Do not
use the local M1 Compose file as a public deployment.

See [deployment](docs/DEPLOYMENT.md) for the planned operator workflow and
current deployment blockers, and [releasing](docs/RELEASING.md) for release
gates and package rules.
