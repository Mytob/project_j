# Testing

## Strategy

Tests are layered: focused Go package tests, then targeted integration tests,
then the complete release gate. A mandatory test is not skipped silently. A
test requiring a Linux host, kernel capability, or public DNS must be listed as
a blocker when unavailable and must not be represented as proven by simulation.

## v1.1 TOTP stage gate status

### Stage 1 — Standalone engine

Stage 1 adds the isolated `internal/totp` engine and tests for RFC 6238 SHA-1
reference vectors, 30-second boundaries, clock skew, invalid input, secret
generation, replay prevention, clock rollback, and concurrent code submission.
The tests use fixed timestamps and generated test secrets.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/totp` — PASS (2026-10-13).
- Full command: `./build.ps1 test` — PASS (2026-10-13), including all Go
  packages and the M1–M6 Docker integration suite on Docker Desktop 29.8.2.
- The first focused run failed because the boundary test expected the wrong
  value. After correcting the test and running `gofmt`, both commands above
  passed.
- Earlier retries were blocked while Docker Desktop was stopped. Docker became
  available after it was reopened; these earlier environment failures are not
  current blockers.

### Stage 2 — Authentication state and persistence

Automated tests cover initial unconfigured state, pending enrollment, incorrect
code and cancellation, successful activation, encrypted-at-rest state, file
permissions, storage corruption and failure, session invalidation, replay
prevention across store reopen, concurrent code consumption, v1.0 migration,
and key/state preservation during update.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/auth ./internal/totp
  ./internal/admin ./internal/deployment` — PASS (2026-10-13).
- Full command: `./build.ps1 test` — PASS (2026-10-13), including all Go
  packages and M1–M6 integration. The first integration attempt found that the
  key fixture volume targeted a file path; after mounting it as a read-only
  directory, the full suite passed.
- Package command: `./build.ps1 package -Version 1.0.0-dev` — PASS on retry
  (2026-10-13). The first attempt had an 8-second transient HTTPS timeout in a
  whitelist request. The successful run validated package secret exclusion,
  offline image loading, fresh install, update, rollback, and password reset.
- No v1.1 feature has been deployed to a live VPS.

### Stage 3 — Web enrolment

The admin dashboard asks for the current administrator password before it
reveals the pending secret and locally generated QR image. Browser automation
uses the pinned Playwright Chromium container on the same isolated HTTPS
Compose network; it exercises actual rendered controls, navigation, bad and
good password checks, QR image loading, a rejected code, cancellation, and
successful activation. The ordinary admin image has no JavaScript runtime.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/admin ./internal/auth
  ./internal/totp` — PASS on 2026-10-13.
- Full command: `pwsh -NoProfile -File .\build.ps1 test` — PASS on
  2026-10-13. The real-browser test passed and the full M1–M6 regression
  suite passed with TOTP active across admin restarts.
- First complete run failed after Compose reran the fixture initializers,
  replacing the test encryption key. The initializers were made idempotent;
  the repeated run passed. This failure confirmed the app denies startup when
  enabled state cannot be decrypted.
- Browser tooling is test-only: Playwright `1.64.0` is pinned in the test
  package lock and `mcr.microsoft.com/playwright:v1.64.0-noble`; no browser
  dependency is added to the deployed admin container.
- No live VPS was used.

### Stage 4 — Login enforcement

With TOTP unconfigured, the existing password-only v1.0-compatible login
remains available. Once enabled, the rendered login form requires both the
administrator password and a six-digit TOTP code. The handler validates both
before creating an authenticated session; the TOTP store persists the replay
checkpoint before reporting success. Missing, malformed, expired, reused,
concurrent duplicate, or unpersistable codes do not create a session. Login
session creation is serialized with TOTP activation so a password-only request
that overlaps activation cannot survive the activation-time session revocation.
Existing login throttling counts failed TOTP attempts too.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/admin ./internal/auth
  ./internal/totp` — PASS on 2026-10-13.
- Full command: `pwsh -NoProfile -File .\build.ps1 test` — PASS on
  2026-10-13, including real Chromium login after setup and the full M1–M6
  regression suite.
- No live VPS was used.

### Stage 5 — Privileged VPS CLI recovery

`proxyctl reset-totp` clears established or pending authenticator material and
requires a fresh enrollment after the unchanged administrator password is
accepted. The resulting session can reach only authenticator setup and logout;
successful enrollment invalidates it and requires a new password-plus-code
login. `proxyctl replace-totp` is accepted only when TOTP is enabled and uses
the same mandatory fresh-enrollment flow. `proxyctl disable-totp` returns to
password-only login. The three commands reject non-root execution. Persistent
changes are saved before only the admin service is recreated; command or
readiness failures restore the prior state and restart the prior admin service.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./cmd/proxyctl ./internal/admin
  ./internal/auth ./internal/deployment ./internal/totp` — PASS on 2026-10-13.
- Full command: `pwsh -NoProfile -File .\build.ps1 test` — PASS on retry
  (2026-10-13), including all Go packages, Chromium enrollment, and the M1–M6
  isolated Docker integration suite. The preceding run had a transient
  8-second HTTPS timeout while posting a whitelist update; the retry passed.
- Automated tests verify real non-root rejection, reset/disable/replace state
  transitions, replacement eligibility, preserved password bytes, state file
  owner/mode, admin-only stop/recreate commands, failed restart rollback,
  recovery-only web session boundaries, required fresh enrollment, and a new
  password-plus-TOTP login afterward.
- No live VPS was used.

### Stage 6 — Full integration and release testing

The release gate exercises the packaged recovery commands and verifies that
TOTP remains enabled across a v1.0-to-v1.1-style package update. It also backs
up and restores the encrypted TOTP state with its separate key, checking that
the replay checkpoint remains consumed. Update rejects an older release before
loading images or changing active configuration. Package extraction restores
execute permission only for the two named Linux executables, even when the
archive was created on Windows.

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 sh -c 'gofmt -w internal/release/package.go
  internal/release/package_test.go && go test ./internal/release
  ./internal/deployment ./tests/deployment/installcheck'` — PASS on
  2026-10-14.
- Package command: `pwsh -NoProfile -File .\build.ps1 package -Version
  1.1.0-dev` — PASS on 2026-10-14. This uses a disposable Docker-in-Docker
  daemon with networking disabled for the shipped package and images.
- Full command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.1.0-dev` — PASS on 2026-10-14, exit 0. The JSON report records the local
  Go, M1–M6, and M7–M9 gates as passed; release readiness remains blocked on
  host-specific checks. No live VPS was used.
- The first package run failed because the Windows-created archive did not
  preserve the executable bit for `proxyctl`; the deterministic extractor fix
  and regression test passed in both the package and full release reruns.

### Authorized operator follow-up — admin controls and update progress

The follow-up adds a password-and-current-TOTP guarded web disable action,
version/build information in the admin dashboard, and milestone progress in
`proxyctl update`. The percentage represents completed milestones, while a
spinner/elapsed indicator (or periodic log messages) keeps long Docker and
readiness waits visibly active.

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.1-dev` — PASS on
  2026-10-14, exit 0. Go tests, M1–M6 integration/browser, and the M7–M9
  offline package checks passed. The package gate verified version and source
  revision metadata on the admin image and loaded all bundled images into an
  isolated daemon. `dist/release-validation-1.1.1-dev.json` records the local
  gate as passed and actual-host checks as blocked.
- Chromium verified dashboard version/build rendering, authenticator disable
  with password and current code, global session revocation, and password-only
  login. Unit tests also reject bad credentials/codes and missing CSRF.
- The new v1.1.1-dev package has not been deployed to the VPS. Actual-host
  checks for this build remain unverified.

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

`build.ps1 test` runs Go unit tests and the M1–M6 Compose integration runner,
including the real-browser TOTP enrollment flow.
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

The full command is `./build.ps1 release`. It runs Go unit tests, the M1–M6
integration suite, and the M7–M9 package/install/update gate in sequence. It
writes `dist/release-validation-<Version>.json` with each local result and an
explicit `blocked` status for checks requiring an actual production host. A
successful local gate does not mean the release is ready to publish.

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
| Updater | Actual offline update, credentials/whitelist/WireGuard/TOTP/site preservation, forced failure recovery, downgrade rejection, active+previous retention, no global prune | PASS 2026-10-14; Ubuntu host checks remain |
| TOTP recovery and backup | Packaged reset/disable/replace commands, encrypted key+state restore, consumed-code replay checkpoint, admin restart | PASS 2026-10-14; no live v1.1 deployment |
| Password reset | Hashed credential replacement, admin-only recreation, existing sessions invalidated by process restart | PASS 2026-10-13; Ubuntu host checks remain |
| Full release | Go tests, M1–M6 integration, M7–M9 package/install/update; JSON report records host-only checks | PASS 2026-10-14; production host checks blocked |

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

### Verified M10 full local release gate — 2026-10-13

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version 1.0.0-dev`
- Result: PASS (exit 0) for all locally runnable gates.
- Covered: Go unit tests and compilation; the complete M1–M6 integration suite;
  package build and offline image validation; actual M8 install and M9 update,
  preservation, rollback, retention, and password-reset checks in isolated
  Docker-in-Docker.
- Report: `dist/release-validation-1.0.0-dev.json`; local gate is `passed` and
  release readiness is `blocked_host_checks_pending`.
- At report generation time, host checks were blocked for Ubuntu 26.04,
  provider ingress, public DNS/ACME, and native Windows setup. The VPS and
  public HTTPS checks were subsequently run as recorded below. Docker
  simulation is not evidence for native Windows behaviour.

### Verified M11 VPS install and public routes — 2026-10-13

- **Target:** Disposable Ubuntu 26.04.1 LTS x86_64 VPS at the user-provided
  public address; Docker Engine 29.9.0. The configured base, admin, and access
  DNS names resolved to that VPS. No credentials, private keys, or deployment
  state are recorded here.
- **Package:** `1.0.0-dev`, rebuilt after PR #12 fixed Docker Engine 29 image
  identity verification.
- **Install command:** `./proxyctl-linux-amd64 install
  ./jellyfin-proxy-1.0.0-dev-linux-amd64.tar.gz`.
- **Install result:** PASS. The installer confirmed all three DNS names,
  started the deployment, waited for readiness, and reported `1.0.0-dev` ready.
  Docker reported the admin, Caddy, and WireGuard services healthy. No
  pre-existing Jellyfin Proxy project was present on the disposable host.
- **ACME/TLS:** PASS. Caddy logs showed successful Let’s Encrypt certificate
  acquisition for `darkcry.com`, `admin.darkcry.com`, and `access.darkcry.com`.
  External `curl.exe` checks reported `ssl_verify_result=0` for each HTTPS
  hostname.
- **External route results:**

  | Hostname | HTTPS status | HTTP status | Result |
  | --- | ---: | ---: | --- |
  | `darkcry.com` | 200 | 308 | Static site served; HTTP redirected to HTTPS. |
  | `admin.darkcry.com` | 200 | 308 | Admin login served; HTTP redirected to HTTPS. |
  | `access.darkcry.com` | 403 | 308 | Empty whitelist denied access; HTTP redirected to HTTPS. |

- **Admin/profile:** PASS. Read-only HTTPS login with the install credential
  opened the dashboard. Two authenticated Windows WireGuard profile downloads
  returned HTTP 200 and matched byte-for-byte. The profile has split-tunnel
  `10.66.66.1/32` routing and 25-second keepalive; the private key was not
  printed or saved to the workstation during this check.
- **Host and namespace firewall:** PASS for observed rules. Host UFW was
  inactive and host `INPUT` policy was `ACCEPT`. The WireGuard container had
  IPv4 and IPv6 ingress chains permitting established traffic, loopback, TCP
  80/443 and UDP 51820, followed by a drop rule; IPv4 also allowed the expected
  WireGuard peer address. The provider panel screenshot showed ingress rules
  for TCP 80/443 and UDP 51820. A later peer handshake verified end-to-end UDP
  reachability.
- **Windows tunnel follow-up (19:49:40 UTC):** `docker compose exec -T
  wireguard wg show` reported a handshake 1 minute 15 seconds earlier, with
  148.56 MiB received and 1.48 MiB sent. The operator reports they can stream
  from the app. The endpoint address and peer keys are intentionally omitted.
- **Whitelist removal:** PASS (operator-confirmed). After removing the
  temporary client whitelist entry, `access.darkcry.com` returned HTTP 403.
- **Windows Firewall follow-up:** The operator reports adding the documented
  inbound TCP 8096 allow rule scoped to remote address `10.66.66.1`; streaming
  continued to work. The operator reports there are no other rules on the
  machine. Windows host gate: PASS (operator-confirmed). See
  `docs/DEPLOYMENT.md` for the rule and removal command.
- **Earlier failure and fix:** The first real install safely rolled back
  because Docker Engine 29's `image inspect .Id` returned an OCI index digest
  rather than the package's platform config digest. PR #12 changed install and
  update verification to hash image config blobs from `docker image save` and
  read archive manifests independently of config entry ordering. A first
  release-gate run then caught config blobs preceding `manifest.json`; the
  corrected verifier uses two passes. The subsequent `./build.ps1 release
  -Version 1.0.0-dev` run passed all local gates.
- **Limits:** VPS install, public HTTPS, DNS, WireGuard handshake, app
  streaming, whitelist removal/default deny, and streaming with the documented
  scoped Windows Firewall rule have passed. The Windows firewall scope report
  is operator-confirmed; no host-specific checks remain open. PR #20 promoted
  the release to `main`, and tag `v1.0.0` plus the downloadable GitHub Release
  are published.

### Verified stable 1.0.0 release gate — 2026-10-13

- **Final command:** `./build.ps1 release -Version 1.0.0 -HostCheckEvidence
  docs/release-host-checks-v1.0.0.json`
- **Result:** PASS (exit 0). Go tests, M1–M6 integration, and the complete
  stable-version package/install/update/rollback gate passed. The report at
  `dist/release-validation-1.0.0.json` records `local_gate: passed` and
  `release_readiness: ready`, including the three actual-host checks.
- **Published bundle:** [GitHub Release v1.0.0](https://github.com/Mytob/project_j/releases/tag/v1.0.0)
  contains `jellyfin-proxy-1.0.0-linux-amd64.tar.gz`, its matching `.sha256`
  file, and `release-validation-1.0.0.json`.
- **First stable-version run:** `./build.ps1 release -Version 1.0.0` failed
  in the offline installer/update gate because retention assertions expected
  the hard-coded starting release `1.0.0-dev`. The harness now derives test
  patch versions from the package manifest. Its version helper unit tests
  passed, and integration HTTP probes now have bounded timeouts.
- **Host evidence:** The version-matched evidence file records the completed
  Ubuntu/VPS, public DNS/ACME/provider firewall, and native Windows checks.
- **Release publication:** PR #20 promoted `dev` to `main` at `350a69f`; the
  `v1.0.0` tag and stable GitHub release were published and verified. One
  post-merge full-gate attempt had a transient curl connection reset in M1–M6;
  the subsequent full release command completed successfully with all checks
  passed.
