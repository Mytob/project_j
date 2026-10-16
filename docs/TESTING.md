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
- The operator subsequently reported deploying v1.1.1-dev and that it worked
  as expected; the follow-up screenshot identified the disable-form layout
  issue corrected by PR #31. The updated 1.1.2-dev package has not been
  deployed, so its version-matched actual-host checks remain unverified.

### Authorized operator follow-up — responsive authenticator-disable form

PR #31 fixes the password and current-code fields wrapping into their labels by
placing each field in a responsive grid. Wider screens show two columns; narrow
screens stack the fields.

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.2-dev` — PASS on
  2026-10-14, exit 0. Go tests, M1–M6 integration/browser checks, and M7–M9
  offline package/install/update/rollback checks passed.
- The generated package is
  `dist/jellyfin-proxy-1.1.2-dev-linux-amd64.tar.gz`. The validation report
  `dist/release-validation-1.1.2-dev.json` records the local gate as passed and
  host-specific readiness as blocked pending version-matched Ubuntu VPS,
  provider-firewall/public ACME, and native Windows checks. The package has not
  been published.

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

### Stable 1.1.2 local release gate — 2026-10-14

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.2`.
- Result: PASS on retry. Go tests, M1–M6 integration (including Chromium
  TOTP disable with password and current code, session revocation, WireGuard
  outage/recovery), and M7–M9 offline package/install/update/rollback/retention
  checks passed. The first run stopped when its PID-derived integration subnet
  collided with an existing empty project test network; the retry selected a
  free subnet. No unrelated Docker resources were removed.
- Package: `dist/jellyfin-proxy-1.1.2-linux-amd64.tar.gz`.
- Host evidence: `docs/release-host-checks-v1.1.2.json` records the operator's
  current 1.1.2-dev build/streaming confirmation and the previously verified
  public DNS, ACME, and provider ingress results for the same VPS.
- Final clean run: After PR #33 merged the evidence into `dev`, the command
  above passed on clean commit `ce3f4e5890e3`. The report recorded
  `local_gate: passed` and `release_readiness: ready`; its admin build number
  is `ce3f4e5890e3`.
- Host evidence: `docs/release-host-checks-v1.1.2.json` records the operator's
  current 1.1.2-dev build and streaming confirmation, plus the same VPS public
  DNS, ACME, provider ingress, and Windows firewall results previously
  verified. Direct DNS lookups from this runner were unavailable, so those
  public-host results carry forward from the documented 2026-10-13 check.
- Package: `dist/jellyfin-proxy-1.1.2-linux-amd64.tar.gz`, SHA-256
  `c8c8d0dcddebd11be02ee90b44319e935ef1f74326a63b8ad6933ea1ce4417ae`.
- Publication: PR #34 promoted the tested `dev` state to `main` at `86bf9c2`;
  tag `v1.1.2` and [GitHub Release v1.1.2](https://github.com/Mytob/project_j/releases/tag/v1.1.2)
  are published with the package, updater, checksums, and validation report.
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

### Verified v1.2.0-dev local release gate — 2026-10-14

- **Command:** `pwsh -NoProfile -File .\build.ps1 release -Version 1.2.0-dev`.
- **Result:** PASS (exit 0) for all mandatory local checks. The report at
  `dist/release-validation-1.2.0-dev.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
- **Go:** All packages passed, including admin, auth/TOTP, Caddy telemetry,
  monitoring/history, deployment, release packaging, WireGuard, and installer
  checks.
- **Browser and container integration:** Existing M1–M6 and v1.1 journeys
  passed. Chromium covered Statistics navigation, live and historical ranges,
  responsive layouts at 1440/768/390px, keyboard navigation, and authenticated
  SSE reconnect/session expiry. Container checks covered live host metrics,
  read-only metric mounts, unprivileged isolation, restart recovery, and the
  absence of published collector ports, Docker sockets, extra capabilities,
  or host namespaces. The real Caddy module was exercised with concurrent,
  interrupted, range, and WebSocket streams plus allow/deny and byte counters.
- **Package/update:** The 1.2.0-dev archive loaded offline into an isolated
  Docker-in-Docker daemon. Install, namespace firewall rules, monitoring image,
  history persistence, update, forced-failure rollback, retention, and
  password reset passed. The port collision in the forced-failure scenario
  was expected and verified rollback to the working deployment.
- **Host limits:** This run used Windows 11/Docker Desktop's Linux engine. It
  did not deploy to a VPS or exercise Ubuntu 26.04's native host metrics,
  provider firewall/public DNS/ACME, or a native Windows WireGuard client and
  Firewall. Those checks remain pending before release readiness.
- **Artifact:** `dist/jellyfin-proxy-1.2.0-dev-linux-amd64.tar.gz` was built
  and validated locally. It is a generated artifact and is not committed.

### Verified v1.2.0-dev test VPS update — 2026-10-14

- **Target:** User-authorized Ubuntu 26.04.1 LTS x86_64 VPS serving
  `darkcry.com`, `admin.darkcry.com`, and `access.darkcry.com`. The active
  1.1.2-dev services were healthy before update; the root filesystem had
  4.9 GB free.
- **Command:** `./proxyctl-linux-amd64 update
  ./jellyfin-proxy-1.2.0-dev-linux-amd64.tar.gz`.
- **Result:** PASS. Package and persistent TOTP storage validation passed;
  bundled images loaded offline; the updater reported services healthy and
  completed its public HTTPS checks. Admin, Caddy, hostmetrics, and WireGuard
  were healthy after deployment. The package SHA-256 matched the workstation
  copy.
- **Actual host metrics:** The private collector endpoint returned live VPS
  memory (873,529,344 bytes total), root filesystem capacity (9,181,077,504
  bytes), receive/transmit totals, load averages, and uptime. It was not a
  published host port. Docker inspection reported user `65532:65532`, no added
  capabilities, no privileged mode, no host PID/network namespace, and
  read-only `/proc`, `/sys`, and root filesystem mounts.
- **Public routes and authorization:** With normal TLS verification,
  `darkcry.com` returned 200, `admin.darkcry.com` returned 200, and
  `access.darkcry.com` returned 403; TLS verify result was 0 for all three.
  Anonymous `/statistics` redirected to login, and `/statistics/history` and
  `/statistics/events` returned 401. The public collector endpoint remained
  unpublished.
- **Persistence and WireGuard:** Existing TOTP key/state, whitelist files, and
  site content remained present. A populated `data/statistics/2026-10-14.json.gz`
  remained present through an admin-only restart, after which admin was
  healthy. The WireGuard container showed a recent peer handshake following
  the update restart.
- **Build identity:** The deployed image reports version `1.2.0-dev` and build
  `62acf66c2182-dirty`. The package was built from the tested v1.2 working tree
  before commit `eaa14f9`; rebuild from the merged, clean `dev` revision before
  stable promotion.
- **Remaining check:** Native Windows playback was not repeated after this
  update. The operator had previously confirmed the scoped TCP 8096 firewall
  rule and streaming on 1.1.2-dev; the post-update WireGuard handshake was
  observed, but the Windows client still needs a playback confirmation.

### Administrator navigation and component health follow-up — 2026-10-14

- **Focused command:** `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/admin ./cmd/admin` — PASS. Tests
  cover authenticated separate page routes, removed UI fragments, Caddy's
  private health request, and stale/future WireGuard heartbeat rejection.
- **Full integration command:** `pwsh -NoProfile -File .\build.ps1 test` —
  PASS, exit 0. Chromium verified each sidebar link opens a distinct page,
  confirms all six health cards show Healthy in the functioning test stack,
  and runs the existing password/TOTP, statistics, responsive UI, streaming,
  collector and Caddy journeys. Integration also verified the WireGuard
  health heartbeat is readable by the unprivileged admin container.
- **Release command:** `pwsh -NoProfile -File .\build.ps1 release -Version
  1.2.1-dev` — PASS, exit 0. Go tests, M1–M6 plus v1.1/v1.2 browser and
  container integration, and the offline package install/update/rollback,
  retention, and reset checks passed. The report at
  `dist/release-validation-1.2.1-dev.json` records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- **Version-matched VPS update — 2026-10-15:** `proxyctl update` installed
  `1.2.1-dev` on the authorized test VPS. It reported successful service health
  checks and public HTTPS readiness. Compose reported the admin, Caddy,
  hostmetrics, and WireGuard services healthy. `https://darkcry.com/` and
  `https://admin.darkcry.com/` returned HTTP 200 with valid TLS; the
  empty-allowlist `https://access.darkcry.com/` returned HTTP 403 with valid
  TLS. The admin image tag was `jellyfin-proxy/admin:1.2.1-dev`.
- **Host limits:** Windows WireGuard-client playback has not yet been checked
  after this package update. The generated release report continues to mark
  host-specific readiness blocked pending that client check; the VPS results
  above are version-matched evidence.
- **Artifact:** `dist/jellyfin-proxy-1.2.1-dev-linux-amd64.tar.gz` was built
  and validated locally; it is generated output and is not committed.
- **Source control:** Commit `5c0fb42` was merged into `dev` by [PR #40](https://github.com/Mytob/project_j/pull/40),
  merge commit `4bc5c41`.
- **Reproduction note:** The first clean release-gate attempt was interrupted
  while its isolated integration stack was running, leaving that uniquely
  named test project active. The next run exposed its reserved-port collision.
  The project was removed with its own Compose file and scoped project name;
  the subsequent complete release gate passed.

### v1.3.0-dev local release gate — 2026-10-15

- **Command:** On clean commit `f14737f2db83`, `pwsh -NoProfile -File
  .\build.ps1 release -Version 1.3.0-dev` — PASS, exit 0 at 2026-10-15
  20:18 UTC. The runner reported Go, browser/monitoring
  integration, and offline package/install/update/rollback gates passed.
- **Go and frontend:** All Go packages passed. Frontend typecheck, five Vitest
  tests, and the Vite production build passed.
- **Browser and container integration:** Chromium covered authentication,
  responsive admin pages, health diagnostics, authenticated statistics,
  history/SSE, password change, WireGuard peer lifecycle and config delivery.
  Container checks covered collector isolation and real Caddy streaming,
  range, WebSocket and byte-accounting behavior.
- **Package/update:** Five images loaded into the isolated daemon without
  registry access. Fresh install/readiness, IPv4/IPv6 ingress rules, offline
  update, rollback, retention, credential reset/TOTP recovery, and preservation
  of an unrelated container passed. The intentional port-conflict case also
  verified rollback and left the unrelated container running.
- **Report:** `dist/release-validation-1.3.0-dev.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  The archive is `dist/jellyfin-proxy-1.3.0-dev-linux-amd64.tar.gz` and is
  generated output, not committed.
- **Host limits:** No v1.3 deployment to a VPS or native Windows WireGuard,
  firewall, and playback verification was performed. Those checks remain
  blocked and the v1.2 evidence does not satisfy them.
- **Dependency audit:** `npm audit` reported zero vulnerabilities for both
  frontend lockfiles. `govulncheck` found no vulnerable reachable symbols;
  one no-fix, module-only advisory applies to unused `golang.org/x/crypto/openpgp`.
  Docker Scout was not run after the automatic approval reviewer rejected
  external transfer of private-image SBOM/package metadata. Full evidence is in
  `docs/DEPENDENCY_AUDIT_V1.3.md`.
- **Source control:** [PR #43](https://github.com/Mytob/project_j/pull/43) was
  merged into `dev` at `98012d6`. This is an integration merge only; the v1.3
  host-specific release checks remain pending.

### v1.3 chart and browser-gate follow-up — 2026-10-15

- **Changes:** Commit `693c65d363f477b750b5423990e547bfc2ac8af5` adds
  pointer and keyboard chart selection, keeps the chart control area stable
  when a series has fewer than two samples, and records desktop/mobile
  screenshot baselines for Overview, Statistics, Health, Access Control,
  WireGuard, and Security. Browser smoke checks exercise Chromium, Firefox,
  and WebKit. The dependency audit now records the pinned npm 12.2.0, xcaddy
  0.4.7, and Playwright 1.64.1 toolchain.
- **Focused integration:** `pwsh -NoProfile -File
  .\tests\integration\run.ps1` — PASS on 2026-10-15; all 4 Playwright tests
  passed across the three engines, alongside M1–M6, WireGuard, Caddy stream,
  collector, history/SSE, password/TOTP, peer rotation, and config download
  checks. Vitest ran 6 tests and the production frontend build passed.
- **Clean-tree release:** On `693c65d363f477b750b5423990e547bfc2ac8af5`,
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.0-dev` — PASS,
  exit 0 at 2026-10-15 21:14 UTC. Go, three-engine browser/container
  integration, and offline package install/update/rollback all passed.
  `dist/release-validation-1.3.0-dev.json` records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`; the Linux amd64 package is
  generated under `dist/` and is not committed.
- **Failures and fixes:** Initial follow-up runs exposed an incorrect chart
  target/selection expectation, a missing Security-route navigation in the
  TOTP test, and unstable screenshot heights from conditionally rendered chart
  controls and changing health-event history. The chart test now selects an
  explicit point, the test navigates to Security before its authenticator
  check, and the screenshots use fixed chart controls and omit volatile health
  history rows. The final isolated integration and clean-tree release runs
  passed.
- **Host checks:** No v1.3 deployment, VPS/kernel/provider-firewall/ACME check,
  native Windows client/firewall test, or playback check was performed. These
  remain blocked; v1.2 host evidence does not satisfy them.
- **Source control:** [PR #45](https://github.com/Mytob/project_j/pull/45)
  merged to `dev` at `658e8da` after the clean local gate passed.

### v1.3 authorized UI and container-health follow-up — 2026-10-16

- **Overview:** The overall health summary and compact status of every
  component now share one panel. It contains no statistics cards, charts, or
  diagnostic detail; those remain on Statistics and Health. Desktop/mobile
  screenshot baselines and browser assertions were updated.
- **Security and observation:** Password changes require a fresh TOTP code
  whenever TOTP is enabled. A dedicated private observer reports container
  state for labeled application containers through fixed GET-only Docker API
  calls; the Docker socket is not mounted in admin or host-metrics.
- **Integration:** `pwsh -NoProfile -File
  .\tests\integration\run.ps1` — PASS. All four Playwright tests passed,
  including Chromium, Firefox, and WebKit navigation/chart checks and the
  Chromium authentication, responsive-page, password/TOTP, one-time
  WireGuard-config download, and container-health flow.
- **Release gate:** `pwsh -NoProfile -File .\build.ps1 release -Version
  1.3.0-dev` — PASS, exit 0 at 2026-10-16 00:29:52 UTC. All Go packages,
  frontend typecheck/six Vitest tests/production build, browser and monitoring
  integration, and offline package install/update/preservation/rollback/
  retention/password-reset checks passed. Six images loaded without registry
  access. `dist/release-validation-1.3.0-dev.json` records
  `local_gate: passed`; the package under `dist/` is generated output and is
  not committed.
- **Host checks:** The report correctly leaves release readiness blocked
  pending a version-matched Ubuntu VPS/provider-firewall/ACME run and native
  Windows WireGuard/firewall/playback verification. No v1.3 deployment was
  performed.
- **Source control:** [PR #47](https://github.com/Mytob/project_j/pull/47)
  merged to `dev` at `f9fed92` after the local release gate passed.

### v1.3.1-dev release gate and VPS update — 2026-10-16

- **Build:** On clean source commit `9e1b7b943805`,
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.1-dev` — PASS,
  exit 0. Go packages, frontend typecheck/six Vitest tests/production build,
  Chromium/Firefox/WebKit browser and monitoring integration, and offline
  package install/update/preservation/rollback/retention/password-reset checks
  passed. Six images loaded without registry access. The report is
  `dist/release-validation-1.3.1-dev.json`; it records local gate passed and
  host checks pending. The generated package is not committed.
- **Package:** `dist/jellyfin-proxy-1.3.1-dev-linux-amd64.tar.gz`, SHA-256
  `f777383345dbe101cf77bea4522b5ca90ff23be49c087db0530da03b7a3a0b5a`.
  `dist/proxyctl-linux-amd64` SHA-256:
  `ddfbcd196db536f9169096645fa7571aba0643b873db0125c408eb99980fda06`.
  Both transferred VPS copies matched these checksums.
- **VPS update:** On the user-authorized Ubuntu 26.04.1 LTS x86_64 host,
  `./proxyctl-linux-amd64 update
  ./jellyfin-proxy-1.3.1-dev-linux-amd64.tar.gz` — PASS. The updater reported
  successful package and persistent TOTP verification, image loading,
  configuration validation, service restart, health checks, and completion.
- **Container state:** Compose reported admin, Caddy, containerhealth,
  hostmetrics, and WireGuard all running and healthy on `1.3.1-dev` images.
  This confirms the observer service itself is healthy; its container-health
  UI was not separately inspected during this deployment.
- **Public routes:** VPS `curl` with normal TLS verification returned
  `darkcry.com` 200, `admin.darkcry.com` 200, and `access.darkcry.com` 403;
  all three reported `ssl_verify_result=0`.
- **Limits:** No native Windows WireGuard/firewall/playback verification was
  performed for this update. The v1.3 host release gate remains blocked on
  those Windows checks; successful VPS installation and HTTPS do not imply
  those checks passed.

### v1.3.2-dev one-time WireGuard download and VPS update — 2026-10-16

- **WireGuard lifecycle:** The stored Windows configuration can be downloaded
  once. A completed response removes the server copy; interrupted transfers
  keep it available for retry. Peer regeneration is blocked until the stored
  configuration is consumed, and the admin UI only shows regeneration after
  that point. The manual delete endpoint was removed so it cannot bypass the
  download-before-rotation gate.
- **Release gate:** On clean source commit `b9955bb94501`,
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.2-dev` — PASS,
  exit 0. Go, Chromium/Firefox/WebKit browser and monitoring integration, and
  offline package install/update/preservation/rollback/retention/password-reset
  gates passed. The JSON report is
  `dist/release-validation-1.3.2-dev.json`; it correctly leaves overall release
  readiness blocked pending native Windows client/firewall checks.
- **Package:** `dist/jellyfin-proxy-1.3.2-dev-linux-amd64.tar.gz`, SHA-256
  `768dd748dbffed5a2f3498300d13a3066f6f0b3b9cc8d1aeeedb2ef4c025115c`.
  `dist/proxyctl-linux-amd64` SHA-256:
  `ddfbcd196db536f9169096645fa7571aba0643b873db0125c408eb99980fda06`.
  Both transferred files matched their local checksums on the VPS.
- **VPS update:** The package updater completed successfully on the user-
  authorized Ubuntu 26.04.1 LTS x86_64 VPS and retained the active and previous
  release. Admin, Caddy, containerhealth, hostmetrics, and WireGuard all report
  healthy on `1.3.2-dev`; the admin image build label is `b9955bb94501`.
- **Public routes:** Requests with normal TLS verification returned
  `darkcry.com` 200, `admin.darkcry.com` 200, and `access.darkcry.com` 403;
  each reported `ssl_verify_result=0`.
- **Limits:** No native Windows client import, firewall, or playback check was
  performed for this update. The release report remains blocked on those
  Windows checks.

### v1.3.3-dev WireGuard config deletion permission repair — 2026-10-16

- **Root cause:** VPS admin logs showed `permission denied` when deleting
  `windows.conf`. The bind-mounted `data/wireguard-client` directory was
  `root:root` mode 0755, so the unprivileged admin process (UID 65532) could
  read and return the file but could not consume it.
- **Immediate VPS repair:** The directory was changed to `root:65532` mode
  2770. A disposable sentinel file was removed successfully from inside the
  admin container as UID 65532. The live Windows config was not read or
  consumed during diagnosis.
- **Code fix:** The updater now restores this directory's ownership and
  permissions on every update. The update regression test first changes the
  directory to `root:root` mode 0755 and verifies repair to `root:65532` with
  group write access.
- **Validation:** `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0;
  all Go packages and all four Playwright tests passed. Clean-tree
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.3-dev` — PASS,
  exit 0; frontend typecheck/six tests/build and offline install/update/rollback
  gates also passed. The release report records the local gate as passed and
  native Windows checks as pending.
- **VPS update:** The 1.3.3-dev package updater completed successfully and
  retained both active and previous releases. The user can now download the
  pending configuration once; the server-side endpoint was not invoked during
  diagnosis so the user's pending config remained available.

### v1.3.4-dev WireGuard transient notices and test VPS update — 2026-10-16

- **Behavior:** Peer-rotation confirmation and configuration download success
  or failure notices dismiss after five seconds. The `rotated` query marker is
  removed from the address bar once the confirmation has been rendered.
  Persistent configuration state and safety guidance remain visible.
- **Browser coverage:** The Chromium admin flow verifies the rotation notice,
  simulates a failed config request and checks its alert expires, then performs
  the one-time download and checks its success notice expires while the peer
  regeneration guidance remains visible.
- **Validation:** `.\build.ps1 test` — PASS, exit 0; Go tests and all four
  Playwright browser tests passed, including Firefox/WebKit admin smoke checks
  and the Chromium authentication/WireGuard flow.
- **Release gate:** Clean-tree `.\build.ps1 release -Version 1.3.4-dev` on
  merged `dev` commit `f8d530a70abf` — PASS, exit 0. Go tests, frontend
  typecheck/six unit tests/build, all four browser integration tests, and
  offline package install/update/rollback/retention/password-reset checks
  passed. `dist/release-validation-1.3.4-dev.json` records
  `local_gate: passed`; native Windows checks remain pending.
- **Package:** `dist/jellyfin-proxy-1.3.4-dev-linux-amd64.tar.gz`, SHA-256
  `e5b01ef58f716d35946be30db1bff9cbf8b6e686f66dc28fbbf8bbde324d656d`.
  `dist/proxyctl-linux-amd64`, SHA-256
  `78dabc8433a93079fcff87eeb18facfaf89f366480b360af91bb05f68ef3c04b`.
  Both VPS transfer checksums matched.
- **VPS update:** The package updater completed successfully on the
  user-authorized Ubuntu 26.04.1 LTS VPS. All five containers report healthy;
  the admin image is `1.3.4-dev` at revision `f8d530a70abf`. No WireGuard
  configuration download or deletion operation was run during this update.
- **Public routes:** Normal TLS verification returned `darkcry.com` 200,
  `admin.darkcry.com` 200, and `access.darkcry.com` 403; all reported
  `ssl_verify_result=0`.
- **Limits:** Native Windows WireGuard import, firewall, and playback checks
  were not performed for this update.
