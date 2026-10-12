# Testing

## Strategy

Tests are layered: focused Go package tests, then targeted integration tests,
then the complete release gate. A mandatory test is not skipped silently. A
test requiring a Linux host, kernel capability, or public DNS must be listed as
a blocker when unavailable and must not be represented as proven by simulation.

## Local environment

M1–M6 Windows checks use PowerShell 7, Go 1.24+, Docker Desktop's Linux engine,
and Docker Compose v2. WSL2 is intended for Linux-specific packaging and
network checks. Do not run the local M1 Compose project as a public service.

## Commands

```powershell
go test ./...
./build.ps1 test
./build.ps1 package -Version 1.0.0-dev
```

`build.ps1 test` runs Go unit tests and the M1–M6 Compose integration runner.
The runner builds the Go admin and mock Jellyfin images, starts a uniquely
named temporary Compose project, verifies routing, authentication, and access
control, exercises protected WireGuard config generation and authenticated
repeat downloads plus the encrypted tunnel outage and recovery, then removes
only that project's containers, network, volumes, and
images. It publishes test web ports on loopback only.

`build.ps1 package -Version 1.0.0-dev` also runs those gates, builds the
Linux/amd64 `admin` and `proxyctl` binaries and deployment images, creates a
versioned archive with its manifest and templates, validates image identities
by loading the archive into an isolated Docker-in-Docker daemon with networking
disabled, then installs the actual archive in that daemon. It verifies the
IPv4/IPv6 namespace ingress filters and that installation leaves the host INPUT
rules unchanged, removes the fresh fixture, forces a host-port collision, and
confirms failed-install cleanup leaves the unrelated conflict container
running.

The full command is `./build.ps1 release`; it must be expanded to cover each
mandatory release check before M10 can pass.

## Test coverage matrix

| Area | Planned automated coverage | Status |
| --- | --- | --- |
| M1 Caddy HTTP/HTTPS, site, mock forwarding, unpublished mock port | Compose integration | PASS 2026-10-12 |
| Whitelist parsing and enforcement | Unit + Caddy integration, empty default deny, spoofed headers | PASS 2026-10-12 |
| Authentication and sessions | Unit + HTTPS integration, expiry, logout, CSRF, attempts, persistence | PASS 2026-10-12 |
| Live Caddy updates | Unix socket integration, invalid update and rollback, concurrency, restart persistence | PASS 2026-10-12 |
| WireGuard | Encrypted tunnel from mock peer to mock Jellyfin; outage and recovery | PASS 2026-10-12 |
| Windows client config | Key/config validation, repeat authenticated downloads, restricted permissions, persistence | PASS 2026-10-12 |
| Package | Extract/verify manifest and load images in an isolated Docker daemon without registry access | PASS 2026-10-12 |
| Installer | Actual package install, IPv4/IPv6 namespace firewall, host INPUT preservation, forced startup rollback, unrelated container preservation | PASS 2026-10-13; Ubuntu host checks remain |
| Updater | Actual offline update, credentials/whitelist/WireGuard/site preservation, forced failure recovery, active+previous retention, no global prune | PASS 2026-10-13; Ubuntu host checks remain |
| Password reset | Hashed credential replacement, admin-only recreation, existing sessions invalidated by process restart | PASS 2026-10-13; Ubuntu host checks remain |
| Full release | All prior gates, package compatibility, restart and unrelated Docker resource checks | Not implemented; M10 |

## Host-specific limitations

Local Caddy TLS verifies hostname routing but does not prove public ACME
certificate issuance. Docker simulation verifies the deployment's private
IPv4/IPv6 network-namespace filters, but does not prove Ubuntu host/provider firewall,
public ingress, or VPS routing. The Docker Desktop Linux engine used here
supports a real WireGuard tunnel; this does not validate every target VPS
kernel. Windows Firewall rules and actual Windows
WireGuard client import need host verification. Release readiness must report
these limits explicitly and use VPS preflight checks.

## Results log

### Verified M1 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Native Go was not installed, so `build.ps1` ran `go test ./...` in
  `golang:1.25.2-alpine3.22`.
- Covered: Go package compilation; all three local HTTP hostnames redirect to
  HTTPS; static site served over HTTPS; admin hostname reaches the M1 503
  placeholder; access hostname reaches the mock Jellyfin public-info endpoint
  over HTTPS; mock port has no host binding; containers, network, test volumes,
  and the locally built mock image are removed at completion.
- Limits: This run does not test access control, authentication, WireGuard,
  public ACME, or Ubuntu host firewall behaviour. WSL2 access was denied but
  was not needed for M1.

### Verified M2 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go unit tests ran in the pinned Go 1.25.2 container.
- Covered: IPv4/IPv6/IP/CIDR parsing, CIDR boundaries, invalid and ambiguous
  values, deterministic deduplication, default-deny policy generation,
  versioned persistence, invalid-file rejection, invalid-save preservation,
  actual Caddy empty-list denial, an allowed IPv4 CIDR source, a denied source
  spoofing `X-Forwarded-For`, and no forwarding of denied requests to mock
  Jellyfin.
- Limits: IPv6 parsing and boundary enforcement are unit tested; live Docker
  client traffic in this test environment is IPv4. The run does not prove
  public VPS firewall behaviour.

### Verified M3 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go unit tests ran in the pinned Go 1.25.2 container.
- Covered: salted PBKDF2 password hashes and verification; malformed hash
  rejection; credential JSON persistence and 0600 writer permissions; session
  expiry/revocation and constant-time CSRF validation; login throttling;
  unauthenticated dashboard redirect; HTTPS sign-in; Secure, HttpOnly,
  SameSite=Strict cookie flags; bad CSRF/password rejection; valid login;
  logout and session invalidation; 429 after five failed attempts; prior M1/M2
  routing, default-deny, spoofed-header, and mock isolation checks.
- Limits: Integration uses local Caddy TLS and a disposable credential fixture.
  It does not establish public certificate behaviour or production VPS file
  ownership/permissions.

### Verified M4 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go unit tests ran in the pinned Go 1.25.2 container.
- Covered: authorized whitelist view/add/remove; invalid and duplicate entry
  rejection; canonical IPv4 CIDR and IPv6 entries; live Caddy configuration
  updates over a permissioned Unix socket; immediate allow/deny effect;
  persistence and Caddy policy restoration after admin restart; admin and
  Caddy API have no published host ports; transaction unit tests for activation
  failure, persistence failure, and concurrent modifications.
- Limits: IPv6 is parsed, managed, persisted, and rendered into Caddy config,
  but live client traffic in this Docker test network is IPv4. Production VPS
  socket ownership and WireGuard routing require later deployment gates.

### Verified M5 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`.
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop Linux engine on
  WSL2 kernel `6.18.33.2-microsoft-standard-WSL2`; Docker Compose 5.6.0.
- Covered: ephemeral WireGuard key generation; kernel WireGuard interface
  creation; encrypted peer handshake and access to mock Jellyfin over the
  tunnel; loss of Jellyfin reachability when the server tunnel is taken down;
  recovery after the home peer initiates a new handshake; Jellyfin has no
  published port; admin and Caddy API remain private; prior M1–M4 checks.
- Limits: This validates the Docker Desktop Linux kernel and test topology.
  It does not establish Ubuntu VPS firewall rules, public UDP ingress, Windows
  WireGuard client configuration, or production deployment.

### Verified M6 run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 test`.
- Result: PASS (exit 0).
- Covered: generated X25519 keys and valid server/Windows peer configs;
  `/32` split routes and 25-second keepalive; atomically retained pair and
  repeated generation without key rotation; authenticated config download,
  repeated byte-identical download and persistence after admin restart;
  no-store response headers; rejection of anonymous downloads, malformed
  configs, and broad file permissions; client config mode 0640 for only the
  admin group; root-only server config mode 0600; server private config absent
  from admin mounts; all M1–M5 gates including real tunnel outage/recovery.
- Limits: The test uses Linux container permission checks. Native Windows
  import and Windows Firewall behaviour still need host verification.

### Verified M7 package run — 2026-10-12

- Command: `pwsh -NoProfile -File .\build.ps1 package -Version 1.0.0-dev`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go tests ran in the pinned Go 1.25.2 container.
- Covered: all Go and M1–M6 integration gates; standalone Linux/amd64 admin
  binary; production admin and WireGuard images; bundled Caddy and Alpine
  images; archive contents and SHA-256 file manifest; required runtime
  templates; exclusion of runtime secrets; and image loading plus
  platform-specific config digest verification in a temporary Docker-in-Docker
  daemon with networking disabled.
- Artifact: `dist/jellyfin-proxy-1.0.0-dev-linux-amd64.tar.gz`.
- Limits: This validates package construction and offline image loading; M8
  separately exercises actual package installation in an isolated daemon.

### Verified M8 installer package run — 2026-10-13

- Command: `pwsh -NoProfile -File .\build.ps1 package -Version 1.0.0-dev`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go tests ran in `golang:1.25.2-alpine3.22`.
- Covered: all Go tests and M1–M6 integration gates; Linux/amd64 `proxyctl` and
  app images; package hash/manifest checks; offline image loading; actual
  installer execution in isolated Docker-in-Docker; install directory and
  health checks; installed IPv4/IPv6 WireGuard-namespace HTTP/HTTPS/UDP allow
  rules and catch-all drops; unchanged host INPUT firewall; port-collision
  startup failure; removal of partial app files; and continued operation of the
  unrelated port-conflict container.
- Limits: the host reported transient WireGuard peer connection retries during
  the established M1–M6 suite, but that integration suite passed. This is not
  an Ubuntu VPS/provider-firewall, public ACME, public ingress, native Windows
  WireGuard import, or Windows Firewall test.

### Verified M9 update and recovery package run — 2026-10-13

- Command: `pwsh -NoProfile -File .\build.ps1 package -Version 1.0.0-dev`
- Result: PASS (exit 0).
- Host: Windows 11 x64; PowerShell 7.6.5; Docker Desktop 29.8.2; Compose
  5.6.0. Go tests ran in `golang:1.25.2-alpine3.22`.
- Covered: all Go and M1–M8 gates; actual offline package update in the isolated
  daemon; preservation of administrator credential, whitelist, server/client
  WireGuard config, and site content; retention of active and previous release;
  forced public HTTPS failure and successful restoration of the previous
  release; successful retry and pruning only older version directories;
  password reset with a healthy admin-only container recreation; and the
  unrelated port-conflict container remaining running.
- Limits: this is Docker-in-Docker on Docker Desktop, not an Ubuntu 26.04 VPS or
  provider-firewall test. Public ACME and native Windows client/Firewall setup
  remain host-specific.
