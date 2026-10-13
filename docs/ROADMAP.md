# Implementation roadmap

Status is based on behaviour and recorded test evidence, not file presence.
No milestone is marked complete until its mandatory tests pass.

## Current status

### v1.1 — TOTP administrator authentication

The user-approved v1.1 scope adds only RFC 6238 TOTP protection for the
administrator interface, with local privileged CLI recovery. Work is staged;
later stages must not begin before the current stage's automated gate passes.

| Stage | Status | Evidence / blocker |
| --- | --- | --- |
| 1 — Standalone TOTP engine | **Complete** | `internal/totp` implements RFC 6238 six-digit SHA-1 codes, secure secret generation, bounded skew, constant-time comparisons, and replay prevention under concurrent verification. Focused `go test ./internal/totp` and `./build.ps1 test` passed on 2026-10-13; PR #23 merged to `dev` as `2ea9bf2`. The first test run exposed a boundary expected-value mistake that was corrected before the passing runs. |
| 2 — Authentication state and persistence | **Complete** | `internal/auth` persists pending/active TOTP states using AES-GCM and a separate 256-bit key; missing, corrupt, or partial state fails closed. Installer provisions the protected files; updater migrates v1.0 and preserves active state. Focused tests, full `./build.ps1 test`, and `./build.ps1 package -Version 1.0.0-dev` passed; [PR #24](https://github.com/Mytob/project_j/pull/24) merged to `dev` as `7fe172e`. |
| 3 — Web enrolment | **Complete** | Server-rendered setup requires fresh password verification before secret/QR display, generates a local PNG QR, confirms a six-digit code, supports cancellation, and revokes sessions after activation. Real Chromium tests exercise rendered controls and the full enrolment journey through the HTTPS test route. `./build.ps1 test` passed; [PR #25](https://github.com/Mytob/project_j/pull/25) merged to `dev` as `9de712c`. |
| 4 — Login enforcement | **Complete** | Enabled TOTP is required with the password for every new admin session. Persistent replay checks, shared login throttling, fail-closed storage errors, and concurrent login tests pass. Browser and full regression gate passed on 2026-10-13; PR #26 merged to `dev` as `298224d`. |
| 5 — Privileged VPS CLI recovery | **Complete** | Root-only `reset-totp`, `disable-totp`, and `replace-totp`; replacement is enabled-only and requires a verified new enrollment before normal access returns. Recovery sessions are limited to setup/logout. Focused Go tests and `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-13; PR pending. |
| 6 — Full integration and release testing | Not started | Begins after Stage 5 passes; package, v1.0 upgrade, backup/restore, rollback and downgrade guard release gate required. No live VPS deployment. |

The execution plan follows the supplied implementation brief in order:
standalone engine; auth state/persistence; web enrolment; login enforcement;
root-only VPS CLI recovery; full local integration and release validation.
No live VPS deployment is part of v1.1 testing.

#### Stage 5 evidence — 2026-10-13

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./cmd/proxyctl ./internal/admin
  ./internal/auth ./internal/deployment ./internal/totp` — PASS.
- `pwsh -NoProfile -File .\build.ps1 test` — PASS on retry. The first
  integration attempt failed on an 8-second HTTPS timeout during a whitelist
  request; the repeated complete run passed all Go packages, real Chromium
  enrollment, and the M1–M6 Docker integration suite. No tests were skipped.
- Automated coverage includes execution under a non-root UID, recovery,
  disable, enabled-only replacement, state ownership/mode, password-file
  preservation, admin-only restart, failed-restart rollback, mandatory fresh
  enrollment, recovery-session API restrictions, and post-enrollment login.
- Docker Desktop was reopened for this run. No live VPS was used.

#### Stage 1 evidence — 2026-10-13

- `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/totp` — PASS.
- `./build.ps1 test` — PASS, including all Go packages and the M1–M6
  integration suite on Docker Desktop 29.8.2.
- The initial Stage 1 test run exposed an incorrect boundary expected value
  (`TestCodeAndTimeStepBoundaries`); the expected HOTP values were corrected
  and both commands above passed afterward.
- Stage 1 work is on `feature/totp-engine`; [PR #23](https://github.com/Mytob/project_j/pull/23) merged to `dev` as `2ea9bf2`.

#### Stage 2 evidence — 2026-10-13

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/auth ./internal/totp
  ./internal/admin ./internal/deployment` — PASS after correcting a
  fault-injection fixture.
- `./build.ps1 test` — PASS. It includes password-only v1.0-compatible admin
  login, admin container restart, and all M1–M6 integration checks.
- `./build.ps1 package -Version 1.0.0-dev` — PASS on retry. The first run
  encountered an 8-second transient HTTPS timeout during a whitelist test; the
  subsequent full run passed M1–M6, archive secret exclusion, offline image
  loading, fresh install, v1.0 state migration, update preservation, rollback,
  retention, and password reset.
- Initial integration run exposed a test-only named-volume mount at a file
  destination; the fixture now mounts the read-only key directory, matching
  production boundaries. No live VPS was used.
- Stage 2 was implemented on `feature/totp-auth-state`; [PR #24](https://github.com/Mytob/project_j/pull/24) merged to `dev` as `7fe172e`.

#### Stage 3 evidence — 2026-10-13

- `pwsh -NoProfile -File .\build.ps1 test` — PASS after adding the real
  Chromium flow to the existing Docker integration project. It covers
  navigation, rendered setup controls, invalid and valid password
  reauthentication, QR rendering, a rejected code, cancellation, successful
  activation, and the existing M1–M6 regression suite.
- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/admin ./internal/auth
  ./internal/totp` — PASS.
- The first full integration attempt correctly failed closed after a test
  Compose invocation reran fixture initializers, replacing the test key while
  preserving newly enabled state. Both TOTP fixture initializers now preserve
  existing files; the repeated full gate passed, including admin container
  restart with active TOTP state.
- No live VPS was used. Stage 3 was implemented on `feature/totp-enrolment`;
  [PR #25](https://github.com/Mytob/project_j/pull/25) merged as `9de712c`.

#### Stage 4 evidence — 2026-10-13

- Focused command: `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.25.2-alpine3.22 go test ./internal/admin ./internal/auth
  ./internal/totp` — PASS.
- `pwsh -NoProfile -File .\build.ps1 test` — PASS after adding a transition
  lock and a concurrent enrollment-confirmation/password-only-login test. The
  Go suite checks
  password-only login while TOTP is unconfigured; missing, incorrect,
  expired, and reused TOTP codes; session rotation; protected routes; parallel
  duplicate-code login; and fail-closed replay-state writes. Real Chromium
  completes enrollment, rejects an incorrect login code, accepts the
  password-plus-code login, signs out, and confirms reuse is rejected.
- The browser enrollment journey now runs after password-only regression tests
  and then restarts the admin container with TOTP enabled, avoiding state
  coupling with the v1.0 compatibility checks.
- No live VPS was used. Stage 4 was implemented on `feature/totp-login` and
  merged through [PR #26](https://github.com/Mytob/project_j/pull/26) to `dev`
  as `298224d`.

| Milestone | Status | Evidence / blocker |
| --- | --- | --- |
| M1 — Minimal working proxy | Complete | `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-12; see test log below. |
| M2 — Default-deny IP whitelist | Complete | Go unit tests and live Caddy/Docker enforcement passed on 2026-10-12. |
| M3 — Administrator authentication | Complete | PR #3 merged as `0b1b11f`; Go tests and M1–M3 integration passed. |
| M4 — Admin whitelist management | Complete | `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-12. |
| M5 — WireGuard connectivity | Complete | PR #5 merged as `19fa619`; real encrypted tunnel, outage, recovery, and prior integration checks passed on 2026-10-12. |
| M6 — Windows WireGuard configuration | Complete | PR #6 merged as `f05fc7b`; authenticated repeat downloads, restart persistence, split routes, keepalive, and restricted permissions verified. |
| M7 — Self-contained release packages | Complete | `pwsh -NoProfile -File .\build.ps1 package -Version 1.0.0-dev` passed on 2026-10-12; the archive manifest and all four images validated in an isolated daemon. |
| M8 — Guided VPS installer | Complete | `build.ps1 package -Version 1.0.0-dev` passed on 2026-10-13; real package installed and forced-startup failure rolled back in isolated Docker-in-Docker. |
| M9 — Updater, recovery, retention | Complete | `build.ps1 package -Version 1.0.0-dev` passed on 2026-10-13 with actual offline update, data preservation, forced-failure recovery, two-release retention, and password-reset checks. |
| M10 — Full automated release validation | Complete | PR #10 merged as `da9d281`; `build.ps1 release -Version 1.0.0-dev` passed all local gates on 2026-10-13 and explicitly blocks readiness pending production-host checks. |
| M11 — Version 1.0.0 release | Complete | PR #20 promoted the validated tree to `main` at `350a69f`; tag `v1.0.0` and the GitHub release are published with the self-contained package, SHA-256 checksum, and ready validation report. |

Documentation commit `c8aedb7` is on `main`. M1 commits `613ff18` and
`5c7217f` were merged into `dev` through [PR #1](https://github.com/Mytob/project_j/pull/1)
at merge commit `f042820`. M2 commit `5f285cb` was merged through
[PR #2](https://github.com/Mytob/project_j/pull/2) at merge commit `e81e422`.
M3 commit `18c6a96` was merged through
[PR #3](https://github.com/Mytob/project_j/pull/3) at merge commit `0b1b11f`.
M4 commit `7954bfb` was merged through
[PR #4](https://github.com/Mytob/project_j/pull/4) at merge commit `024b7f2`.
M5 commit `5e7fcb3` was merged through
[PR #5](https://github.com/Mytob/project_j/pull/5) at merge commit `19fa619`.
M6 commit `6451858` was merged through
[PR #6](https://github.com/Mytob/project_j/pull/6) at merge commit `f05fc7b`.
M7 was merged through [PR #7](https://github.com/Mytob/project_j/pull/7) at
merge commit `ae72a39`.
M8 was merged through [PR #8](https://github.com/Mytob/project_j/pull/8) at
merge commit `7470ef3`.

## Milestone plan

### M1 — Minimal working proxy

- **Status:** Complete
- **Dependencies:** Empty repository bootstrap.
- **Deliverables:** Go module, Caddy local TLS configuration, static site,
  isolated mock Jellyfin service, Compose integration environment, and
  repeatable PowerShell test/cleanup runner.
- **Tests:** Verify the three local HTTP hostnames, local HTTPS routing, static
  content, mock Jellyfin forwarding, and that the mock has no published host
  port.
- **Gate:** All foundation tests pass on Windows with Docker Desktop.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 test` passed on
  Windows 11 x64 with Docker Desktop 29.8.2 and Compose 5.6.0. Go package
  compilation ran in the pinned Go 1.25.2 container because native Go was
  absent. The integration runner built the mock image, checked HTTP→HTTPS
  redirects for all hostnames, checked HTTPS static/admin/access routes,
  verified the mock Jellyfin response, asserted no published mock port, and
  cleaned up its containers, network, volumes, and local image. Exit status: 0.
- **Open issues:** WSL2 access was denied in this session. M1 does not require
  WSL2; Linux-host-specific milestones still need a capable host.

### M2 — Default-deny IP whitelist

- **Status:** Complete
- **Dependencies:** M1.
- **Deliverables:** `internal/whitelist` IPv4, IPv6, and CIDR parser; canonical
  versioned JSON persistence with atomic replacement; Caddy policy renderer;
  default deny for empty or invalid configuration; isolated live Caddy tests.
- **Tests:** Allow/deny cases, CIDR boundaries, invalid input, IPv4/IPv6,
  spoofed forwarding headers, empty whitelist, and no unintended mock access.
- **Gate:** All access-control tests pass.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 test` passed on
  Windows 11 x64 using Docker Desktop. Go tests passed for IPv4/IPv6 parsing,
  CIDR boundaries, invalid and ambiguous input, canonicalization, fail-closed
  policy generation, corrupt persistence, and invalid-save preservation. Live
  Caddy tests passed for empty-list 403, CIDR allow, spoofed header rejection,
  and zero Jellyfin forwarding for denied requests.
- **Open issues:** Admin-managed live updates are M4. Actual public VPS firewall
  behaviour remains an Ubuntu host check.

### M3 — Administrator authentication

- **Status:** Complete
- **Dependencies:** M1.
- **Deliverables:** Go admin server, password hashing, secure sessions,
  login/logout, CSRF, login-attempt throttling, and persistent configuration.
- **Tests:** Password verification, session expiry and logout, unauthorized
  requests, CSRF, rate limiting, and persistence.
- **Gate:** All authentication and session tests pass.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 test` passed on
  2026-10-12 after M3 integration was added. Unit tests cover password hash
  format/verification, credential persistence, session expiry/revocation,
  CSRF comparison, and rate limiting. Docker/Caddy integration covers the
  server-rendered admin over local HTTPS, anonymous redirect, secure cookie
  attributes, bad password and CSRF rejection, login/session rotation, logout
  invalidation, and 429 throttling after repeated failures. Earlier M1/M2
  routing and default-deny checks pass in the same run.
- **Open issues:** Production credential ownership must be established by the
  deployment milestone. Public TLS and VPS behaviour are not covered locally.

### M4 — Admin whitelist management

- **Status:** Complete
- **Dependencies:** M2 and M3.
- **Deliverables:** Whitelist interface, private Caddy admin Unix socket,
  transactional live updates, and persistent updates.
- **Tests:** Live activation, invalid input, failed persistence/activation
  recovery, concurrency, and restart persistence.
- **Gate:** All whitelist administration tests pass.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 test` passed on
  2026-10-12. Go tests cover canonical add/remove, duplicate/missing entries,
  concurrent changes, invalid entry handling, and unchanged persisted/live
  state on activation or persistence failure. Docker/Caddy tests verify
  authenticated view/add/remove, default deny, immediate IPv4 CIDR activation
  and removal, IPv6 entry handling, Unix socket operation with no published
  Caddy API or admin port, and policy restoration after admin restart.
- **Open issues:** Live Docker traffic is IPv4; production socket ownership and
  WireGuard integration remain later milestone gates.

### M5 — WireGuard connectivity

- **Status:** Complete
- **Dependencies:** M1; interfaces from M4.
- **Deliverables:** WireGuard container, shared network namespace for Caddy,
  mock home peer and Jellyfin endpoint, health checks, and required network
  permissions.
- **Tests:** Real local tunnel traffic, HTTP forwarding, outage, and recovery.
- **Gate:** Mock Jellyfin is reached through the encrypted tunnel.
- **Completion evidence:** `pwsh -NoProfile -File .\tests\integration\run.ps1`
  passed on 2026-10-12 using Docker Desktop's WSL2 Linux kernel. The test
  generated disposable peer keys, brought up a real WireGuard interface,
  reached mock Jellyfin at its tunnel address, verified reachability failed
  with the server tunnel down, then verified recovery after the home peer
  initiated a fresh handshake. Prior M1–M4 checks passed in the same runner.
- **Open issues:** This proves the local Docker Desktop kernel and integration
  topology, not Ubuntu VPS firewall rules, public UDP ingress, or Windows
  client configuration.

### M6 — Windows WireGuard configuration

- **Status:** Complete
- **Dependencies:** M5.
- **Deliverables:** X25519 key generation, atomically retained protected
  server/Windows peer configurations, `/32` split-tunnel routes, persistent
  keepalive, and an authenticated non-cacheable config download.
- **Tests:** Key and peer syntax, permissions, repeat downloads, and
  persistence.
- **Gate:** Generated config is valid and repeatably downloadable.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 test` passed on
  2026-10-12. Go tests verify X25519 keypair generation, exact host routes,
  config validation, atomic protected persistence, stable re-provisioning,
  rejection of broad permissions and malformed files, and authenticated
  non-cacheable downloads. Docker integration verifies the Windows config is
  downloadable repeatedly and after admin restart, verifies route and
  keepalive values, and checks group-only client file and root-only server
  key permissions. The real WireGuard tunnel and all prior milestone checks
  also pass.
- **Open issues:** Import into the native Windows WireGuard client and the
  Windows Firewall rule still require actual Windows-host verification.

### M7 — Self-contained release packages

- **Status:** Complete
- **Dependencies:** Application and deployment image definitions.
- **Deliverables:** Linux/amd64 admin build, versioned admin/WireGuard images,
  Caddy and Alpine deployment images, Compose/Caddy/site templates, SHA-256
  manifest, and self-contained `.tar.gz` release archive.
- **Tests:** Load the packaged images in a clean Docker environment; validate
  archive contents and package compatibility without registry pulls.
- **Gate:** Package installs and runs without application image registry access.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 package
  -Version 1.0.0-dev` passed on 2026-10-12. It ran Go tests and all M1–M6
  integration checks, built the Linux/amd64 admin binary and production images,
  verified the versioned archive's file hashes, manifest, required files, and
  absence of runtime secrets, then loaded all four images into an isolated
  Docker-in-Docker daemon with networking disabled and confirmed their
  platform-specific config digests. Archive:
  `dist/jellyfin-proxy-1.0.0-dev-linux-amd64.tar.gz`.
- **Open issues:** `proxyctl` is delivered with M8's installer. The archive
  targets Linux/amd64; no ARM64 package is produced.

### M8 — Guided VPS installer

- **Status:** Complete
- **Dependencies:** M7.
- **Deliverables:** Native Linux `proxyctl install`, Ubuntu 26.04 x64
  preflight, Docker/Compose detection, DNS guidance and resolution check,
  initial credentials, WireGuard setup, scoped firewall rules, package load,
  deployment, and readiness checks.
- **Tests:** Fresh install and failure-path tests; preserve existing SSH and
  unrelated firewall rules; ensure failed installs do not leave public access.
- **Gate:** Automated fresh-install and failure-path tests pass.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 package
  -Version 1.0.0-dev` passed on 2026-10-13. The gate ran Go tests and M1–M6
  integrations; built the installer and release images; loaded the archive into
  an isolated daemon without network access; installed the actual package in a
  fresh isolated deployment; checked IPv4 and IPv6 namespace ingress
  allow/drop rules and unchanged host INPUT rules; and forced a public-port
  collision to verify files rolled back while the unrelated conflict container
  remained running.
- **Limits:** No Ubuntu 26.04 VPS or provider firewall was available. Public
  ACME, provider ingress, host/kernel behavior, and the Windows WireGuard and
  Firewall setup require actual host verification. The installer does not
  change host UFW/nftables/iptables; it filters the Docker-published service
  namespace so Docker DNAT cannot expose other ports, and leaves SSH and
  unrelated host policy untouched.

### M9 — Updater, recovery, and retention

- **Status:** Complete
- **Dependencies:** M8.
- **Deliverables:** `proxyctl update` and `proxyctl reset-password`, package
  compatibility checks, health verification, rollback, and retention of the
  active and one prior known-good release.
- **Tests:** Update success/failure, rollback, data preservation, release
  retention, restart behaviour, and no global Docker pruning.
- **Gate:** Update and recovery tests pass.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 package
  -Version 1.0.0-dev` passed on 2026-10-13. In addition to Go tests and M1–M8
  gates, the actual package was installed in isolated Docker-in-Docker, updated
  offline twice, and checked for preservation of the credential, whitelist,
  WireGuard keys, and site files. A forced HTTPS readiness failure restored the
  previous Compose release; successful retry retained only active and previous
  version directories. Password reset changed the credential and recreated
  only the admin container. The unrelated port-conflict container remained
  running.
- **Limits:** No Ubuntu 26.04 host was available. These checks do not establish
  provider firewall, public ACME, or native Windows setup behavior.

### M10 — Full automated release validation

- **Status:** Complete (local release gate); release readiness remains blocked
- **Dependencies:** M1–M9.
- **Deliverables:** Complete `build.ps1 release` runner, sequential execution of
  locally runnable gates, and a machine-readable report that explicitly lists
  host-specific checks as blocked when no production host is available.
- **Tests:** Full required suite from the specification; mandatory checks may
  not be silently skipped.
- **Gate:** All locally runnable checks pass; host-only limitations are
  explicitly reported. PASS on 2026-10-13.
- **Completion evidence:** `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.0.0-dev` passed Go tests, all M1–M6 integration checks, and the
  actual M7–M9 offline packaging/install/update suite in isolated Docker-in-
  Docker. Report: `dist/release-validation-1.0.0-dev.json`.
- **Original report:** The 1.0.0-dev run correctly marked host checks blocked
  because no actual-host evidence was supplied. M11 later collected that
  evidence and the stable 1.0.0 report records all host checks as passed.

### M11 — Version 1.0.0 release

- **Status:** Complete
- **Dependencies:** M10.
- **Deliverables:** Validated promotion from `dev` to `main`, verified release
  commit and tag, official artifacts where permissions allow, install/update
  docs, and automated first-deployment checks.
- **Tests:** All release gates and artifact verification.
- **Gate:** No mandatory failures; confirm the actual VPS install and public
  routes, then verify the native Windows WireGuard client, recent handshake,
  Jellyfin access through the access hostname, and Windows Firewall scope.
- **Completed preparation:** M10 local release validation passes. The installer
  automatically waits for healthy WireGuard/Caddy/admin services and public
  HTTPS; the isolated package gate exercises installation and rollback. The
  first-deployment procedure is documented in `docs/DEPLOYMENT.md`.
- **VPS evidence (2026-10-13):** The disposable Ubuntu 26.04 x86_64 VPS passed
  guided installation using package `1.0.0-dev`; all services became healthy.
  Let’s Encrypt certificates were obtained for all three hostnames. External
  checks confirmed HTTPS verification succeeds, HTTP redirects to HTTPS, the
  base and admin hostnames return 200, and the access hostname returns 403 with
  the empty whitelist. The authenticated admin dashboard loaded and two
  WireGuard profile downloads matched byte-for-byte. IPv4 and IPv6 namespace
  filters allow only the documented service ports and drop remaining ingress;
  host UFW remained inactive and host INPUT policy remained ACCEPT. The
  provider rule screenshot includes UDP 51820. A later `wg show` confirmed a
  recent handshake and active traffic from the Windows peer.
- **Windows follow-up (2026-10-13):** The operator reports they can stream in
  the app. At 19:49:40 UTC, the VPS reported a handshake 1 minute 15 seconds
  earlier and 148.56 MiB received / 1.48 MiB sent for the peer.
- **Final host gate (2026-10-13):** The operator confirmed the temporary
  whitelist removal returns 403, installed the documented Windows inbound
  TCP 8096 rule limited to `10.66.66.1`, reports there are no other rules on
  the machine, and confirmed streaming still works. Host validation is
  complete based on the operator's report.
- **Release gate (2026-10-13):** `./build.ps1 release -Version 1.0.0
  -HostCheckEvidence docs/release-host-checks-v1.0.0.json` passed Go tests,
  M1–M6 integration, stable-version M7–M9 package/install/update/rollback
  validation, and all three version-matched actual-host checks. The report says
  `release_readiness: ready`. A post-merge integration attempt hit one
  transient curl connection reset; the subsequent full run passed. The first
  stable-version run exposed hard-coded prerelease expectations in the
  install-check harness; these were fixed before the passing run.
- **Published release (2026-10-13):** PR #20 merged the validated `dev` tree
  into `main` at `350a69f`; the `v1.0.0` tag points at that promoted commit.
  [GitHub Release v1.0.0](https://github.com/Mytob/project_j/releases/tag/v1.0.0)
  includes the Linux amd64 deployment package, its SHA-256 checksum, and the
  release validation report.

## Change and test log

| Date (UTC) | Change | Commit / PR | Tests and result |
| --- | --- | --- | --- |
| 2026-10-12 | Initial repository inspection. | None | Docker Desktop 29.8.2 and Compose 5.6.0 present. WSL access denied; native Go absent. |
| 2026-10-12 | M1 local proxy foundation and verified project tests. | `c8aedb7` (docs); `613ff18` (M1); [PR #1](https://github.com/Mytob/project_j/pull/1), merged as `f042820` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M2 whitelist parser, persistence, Caddy policy, and access tests. | Commit `5f285cb`; [PR #2](https://github.com/Mytob/project_j/pull/2), merged as `e81e422` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M3 password auth, file credentials, sessions, CSRF, throttling, and admin HTTPS integration. | Commit `18c6a96`; [PR #3](https://github.com/Mytob/project_j/pull/3), merged as `0b1b11f` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M4 admin whitelist management, private Caddy Unix API, transaction handling, and persistence. | Commit `7954bfb`; [PR #4](https://github.com/Mytob/project_j/pull/4), merged as `024b7f2` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M5 WireGuard peer, shared network namespace, tunnel outage/recovery integration. | Commit `5e7fcb3`; [PR #5](https://github.com/Mytob/project_j/pull/5), merged as `19fa619` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M6 protected peer generation and authenticated Windows config download. | Commit `6451858`; [PR #6](https://github.com/Mytob/project_j/pull/6), merged as `f05fc7b` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M7 production container definitions and self-contained package builder. | Feature branch / PR pending | `pwsh -NoProfile -File .\build.ps1 package -Version 1.0.0-dev` — PASS, exit 0; all four images loaded and verified offline in an isolated daemon. |
| 2026-10-13 | M10 full local release validation runner and JSON blocker report. | [PR #10](https://github.com/Mytob/project_j/pull/10), merged as `da9d281` | `pwsh -NoProfile -File .\build.ps1 release -Version 1.0.0-dev` — PASS, exit 0; local gates pass, production-host checks explicitly BLOCKED. |
| 2026-10-13 | Docker 29 image config digest compatibility fix. | [PR #12](https://github.com/Mytob/project_j/pull/12), merged as `a3239e9` | `./build.ps1 release -Version 1.0.0-dev` — PASS after a first run reproduced the Docker 29 inspect-ID and archive-ordering failures; complete local Go, M1–M6, and M7–M9 gates passed. |
| 2026-10-13 | M11 real VPS install and public routing validation. | [PR #13](https://github.com/Mytob/project_j/pull/13), merged as `04e3a69` | Guided install on Ubuntu 26.04 — PASS; all services healthy, public ACME certificates valid for all hostnames, HTTPS/HTTP redirect/access default-deny and repeat authenticated config download checks PASS. |
| 2026-10-13 | M11 Windows WireGuard tunnel and streaming follow-up. | [PR #14](https://github.com/Mytob/project_j/pull/14), merged as `a72a14b` | VPS `wg show` — PASS, handshake 1m15s before 19:49:40 UTC and active peer traffic; operator reports streaming in the app. |
| 2026-10-13 | M11 final host validation. | [PR #17](https://github.com/Mytob/project_j/pull/17), merged as `a3e0387` | Operator-confirmed whitelist removal returns 403; documented TCP 8096 rule is limited to `10.66.66.1`, no other machine rules are reported, and app streaming continues — PASS. |
| 2026-10-13 | Stable 1.0.0 release gate and deployment bundle. | [PR #18](https://github.com/Mytob/project_j/pull/18), merged as `fd92909` | First `./build.ps1 release -Version 1.0.0` failed because package retention assertions hard-coded `-dev`; final `./build.ps1 release -Version 1.0.0 -HostCheckEvidence docs/release-host-checks-v1.0.0.json` — PASS, `release_readiness: ready`; standalone package installed and updated offline in the isolated Docker daemon. |
| 2026-10-13 | M11 stable release promotion and publication. | [PR #20](https://github.com/Mytob/project_j/pull/20), merged as `350a69f`; tag `v1.0.0`; [GitHub Release](https://github.com/Mytob/project_j/releases/tag/v1.0.0) | Full release gate passed; the self-contained Linux amd64 package, SHA-256 checksum, and `release_readiness: ready` report were uploaded and verified on GitHub. |
| 2026-10-13 | v1.1 Stage 2 encrypted TOTP persistence and v1.0 update migration. | [PR #24](https://github.com/Mytob/project_j/pull/24), merged as `7fe172e` | Focused auth/TOTP/admin/deployment tests, `./build.ps1 test`, and `./build.ps1 package -Version 1.0.0-dev` — PASS; no live VPS used. |
| 2026-10-13 | v1.1 Stage 3 rendered TOTP setup and real-browser coverage. | [PR #25](https://github.com/Mytob/project_j/pull/25), merged as `9de712c` | Focused admin/auth/TOTP tests and `pwsh -NoProfile -File .\build.ps1 test` — PASS; first run exposed non-idempotent TOTP test initializers, corrected and re-run. |
| 2026-10-13 | v1.1 Stage 4 password-plus-TOTP login enforcement. | [PR #26](https://github.com/Mytob/project_j/pull/26), merged to `dev` as `298224d` | Focused admin/auth/TOTP tests and `pwsh -NoProfile -File .\build.ps1 test` — PASS; Go tests cover replay, expiry, concurrency, and storage failure; Chromium covers actual login form use. |
| 2026-10-13 | v1.1 Stage 5 root-only TOTP reset, disable and replace commands with restricted recovery enrollment. | `feature/totp-cli-recovery`, PR pending | Focused proxyctl/admin/auth/deployment/TOTP tests, Windows cross-build, and `pwsh -NoProfile -File .\build.ps1 test` — PASS; see Stage 5 evidence above. |
