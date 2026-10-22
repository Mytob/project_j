# Implementation roadmap

Status is based on behaviour and recorded test evidence, not file presence.
No milestone is marked complete until its mandatory tests pass.

## v1.5 — Audit and quality consolidation

**Status: The `1.5.1-dev` package passed its local release gate and was
deployed to the authorized test VPS. All six services, public routes, and
security checks passed after deployment. The operator subsequently confirmed
playback. Release readiness remains blocked on mobile Safari verification,
direct Windows/provider firewall inspection, accessibility review, comparable
performance measurements, and final changed-code review.**
The baseline was verified as clean `dev` commit
`8562b23f0da21fe9f6c17f8367a30171b72b635b`. Audit coverage, confirmed findings,
security boundaries and the six-page redesign are recorded under
[`v1.5/`](v1.5/CODEBASE_AUDIT.md).

The candidate corrects Linux CPU guest accounting and weighted historical
error rates; shares health probes across requests, avoids unchanged health
state writes and duplicate bootstrap polling; adds CPU alert hysteresis;
changes one-time WireGuard retrieval to authenticated CSRF-protected POST; and
hardens the admin container. The dashboard now separates proxy statistics from
host health, compacts Overview, and uses progressive disclosure for component
details. This remains a development candidate; the `1.5.1-dev` follow-up is
deployed to the authorized test VPS but has not been merged or published. The
running build identifies as `1.5.1-dev`, build `8562b23f0da2-dirty`.

`pwsh -NoProfile -File .\build.ps1 test` and
`pwsh -NoProfile -File .\build.ps1 release -Version 1.5.0-dev` passed on
2026-10-18. The release report records the local gate as passed and host
readiness as blocked. On 2026-10-18, `proxyctl update` deployed it to the
authorized Ubuntu 26.04.1 test VPS. All six containers were healthy with zero
restarts; the private container observer returned healthy snapshots; the admin
container's read-only root, dropped capabilities, no-new-privileges, and 16
MiB `/tmp` restrictions were active. Public TLS checks returned 200 for
`darkcry.com`, 200 for `admin.darkcry.com`, and the expected 403 for
`access.darkcry.com`, all with valid certificates. The two Fail2ban jails,
host SSH journal, and exactly two TCP/22 nftables rules were verified. The
2 GiB swap was active and listed in `/etc/fstab`; a connected WireGuard peer
had a recent handshake and Jellyfin `/health` responded over the tunnel.
Persistent health, TOTP, whitelist, and statistics files remained present,
and the updater retained 1.4.2-dev for rollback. The user confirmed native
Windows playback after this update. Direct Windows firewall/provider
inspection, accessibility checks, and comparable before/after performance
measurements remain open. The later `1.5.1-dev` package includes the admin
session-recovery and UI follow-ups. Its deployment passed the updater, six
container-health checks, TLS 200/200/403 route checks, both Fail2ban jails,
and one-per-family SSH nftables rule check. The peer had no handshake at that
later check, so the earlier playback confirmation does not establish playback
on `1.5.1-dev`; see the dated entry below.
The safe static-analysis findings were corrected; `staticcheck` reports only
32 out-of-scope error-capitalization warnings. The current image scan found no
critical issues; its distinct high findings are triaged in the security audit. Exact evidence is in
[`v1.5/TEST_REPORT.md`](v1.5/TEST_REPORT.md); do not promote until all required
release gates are resolved and explicitly approved.

## v1.6 — Fresh install, recovery, administration and reliability

**Status: The clean dev.17 local release gate and exact-package Ubuntu CLI
update, doctor, and maintenance-service refresh smoke passed. Dashboard
update/rollback acceptance remains open pending a fresh admin sign-in; public
network and native Windows evidence are also pending.**

The v1.6 implementation was merged to dev by [PR #71](https://github.com/Mytob/project_j/pull/71) at c8e279a. Documentation corrections were merged by [PR #72](https://github.com/Mytob/project_j/pull/72) at 432b0db. The clean dev.13 candidate was built from dev commit
432b0db7bc7429f0daa2de83ccfd1b219cffb654. The dev.14 candidate was built
from clean dev commit 78dfb7987946f011e88dc7cde4660c2d24b12142. The clean
dev.15 candidate was built from dev commit
`ebd767615ded1abc6fe776a7c229e8c0784c971b`.

The dashboard maintenance worker now saves its terminal job state before
scheduling a delayed refresh of the restricted maintenance service, preventing
the service from killing its own update process. The clean dev.17 package
passed the local release gate and exact CLI update on a disposable Ubuntu
26.04.1 clone; a delayed systemd refresh smoke also passed. Dashboard update
and rollback remain unverified until the local test admin signs in again. The
fix is in draft [PR #79](https://github.com/Mytob/project_j/pull/79).

On 2026-10-22, `pwsh -NoProfile -File .\build.ps1 release -Version
1.6.0-dev.15 -SupportedUpgradeSources 1.6.0-dev.14` passed. Go tests,
browser/monitoring/security/streaming integration, frontend validation, and
offline package installation, update, rollback and recovery passed. The report
records `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
The exact package updated the disposable Ubuntu 26.04.1 VMware clone from
dev.14; its checksum, pre-update backup, image load, service readiness, and
active/previous release retention passed. `proxyctl doctor` passed on dev.15;
all five containers, the maintenance service, and scheduled backup timer were
healthy/active. The security container read host sshd journal records and
reported both Fail2ban jails. Reserved IPv4/IPv6 test bans reached and cleared
the host nftables sets, whose SSH chain had one TCP/22 drop rule per address
family. A manual 21-file backup verified. After a normal reboot, doctor,
container health, maintenance and backup units, journal access, Fail2ban, and
the exact nftables rules recovered. WireGuard listened on UDP/51820, but no
peer handshake was observed. Public DNS/provider firewall/ACME and native
Windows/client playback remain unverified.

On 2026-10-22, `pwsh -NoProfile -File .\build.ps1 release -Version
1.6.0-dev.14 -SupportedUpgradeSources 1.6.0-dev.13` passed. Go tests,
browser/integration/security/streaming checks, frontend validation, and offline
package installation, update, rollback and recovery passed. The report records
`local_gate: passed` and `release_readiness: blocked_host_checks_pending`.

The exact dev.14 package updated the disposable Ubuntu 26.04.1 VMware clone
`D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` from dev.13. Its transferred
checksum passed; the updater created its pre-update backup, loaded
bundled images, passed service readiness, and retained active and previous
releases. The clone then rolled back to dev.13 with a verified pre-rollback
backup and healthy HTTPS readiness, and updated back to dev.14 using the same
package. The post-update `proxyctl doctor` passed all checks and identified
version 1.6.0-dev.14, build 78dfb7987946. All five containers were healthy;
the maintenance service and scheduled backup timer were active. The security
container reported exactly the `jp-admin` and `jp-ssh` Fail2ban jails, read
actual host sshd journal records, and its host SSH nftables chain contained
the expected IPv4 and IPv6 TCP/22 rules. Reserved documentation IPv4/IPv6
addresses were banned and unbanned successfully, leaving zero active bans.
The WireGuard server interface listened on UDP/51820 and had its peer
configured, but no current peer handshake was observed. The earlier dev.12
disposable-host run covered fresh install/resume, recovery, updater
interruption, restore interruption, low-storage and host-maintenance checks.
A separate clean Ubuntu 26.04.1 clone at
`D:\VM\Ubuntu-v1.6-install-gate\Ubuntu 64-bit.vmx` passed a dev.14 fresh
install, first boot, reboot, HTTPS route, backup, restricted observer
authorization, Fail2ban/journal/nftables, and bounded admin-container recovery
check. The dev.14 package did not repeat the entire destructive failure
matrix. The user-specified `D:\VM\Ubuntu` VM was read-only inspected on dev.6
and left unchanged; no WireGuard handshake or traffic was observed there.

The current candidate adds a resumable keyboard installer, schema-2 .pkg
archives with independent whole-file SHA-256 validation, persistent proxyctl
commands, restricted maintenance observation, a durable fixed-action backup
job API, .bak backup/restore, SQLite statistics history and retention, bounded
diagnostics, and manual host update support. The System dashboard supports
backup/restore, package upload/update, rollback and progress tracking. The
release remains a fresh-install path and does not migrate v1.5.1 data. The
implementation audit and remaining work are tracked in
[v1.6/CODEBASE_AUDIT.md](v1.6/CODEBASE_AUDIT.md).

| Area | Status | Remaining gate |
| --- | --- | --- |
| Go, frontend and browser regression checks | **Passed on clean dev.15** | Host-specific release checks remain open. |
| Offline .pkg install/update/rollback | **Passed on clean dev.15 in local isolated Docker gate** | Six bundled images loaded without registry access. |
| Ubuntu install, recovery and failure acceptance | **Broad dev.12 matrix passed; dev.14 fresh install/reboot; dev.15 exact-package update, reboot, doctor, backup, and host security checks passed** | Full destructive failure matrix was not repeated against dev.15. |
| Public DNS, provider firewall and ACME | **Blocked** | Requires a separate disposable public VPS and test domain. |
| Native Windows WireGuard and firewall | **Blocked** | Requires Windows client and scoped firewall/playback verification. |
| Complete v1.6 stable release | **Not ready** | Public DNS/provider firewall/ACME/internet WireGuard and Windows checks remain unverified. Do not promote or publish dev.15 as stable. |

The clean dev.15 package SHA-256 is
`ea14fd5864fcde11d45d23031adbb3abf9be2ee1d3a1fe0f0ceb3991be668064`;
standalone proxyctl SHA-256 is
`69bf06d16f5da11a475d5ca8cab6101323c6b78d636997a526ffb883868e4b22`. The report
is `dist/release-validation-1.6.0-dev.15.json`. Generated artifacts remain local
under dist; no stable release or production deployment is claimed. See
[TESTING.md](TESTING.md) and [v1.6/VPS_ACCEPTANCE.md](v1.6/VPS_ACCEPTANCE.md)
for evidence and remaining acceptance checks.

## v1.2 — Admin redesign and statistics

The authorized scope is recorded in [V1.2.md](V1.2.md). It adds a responsive
server-rendered admin redesign, containerized host metrics, in-process Caddy
stream instrumentation, authenticated SSE, and bounded 90-day file history.
The local release gate passed on 2026-10-14. The generated report records
`local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
The `1.2.0-dev` package was deployed to the user-authorized test VPS and the
Ubuntu, live host metrics, TLS/routes, isolation, and service-restart checks
passed. Native Windows streaming after this update still needs operator
confirmation. The deployed admin image identifies itself as build
`62acf66c2182-dirty`; build a clean candidate from the merged `dev` revision
before promoting a stable release.

| Stage | Status | Evidence / blocker |
| --- | --- | --- |
| 1 — Requirements and architecture record | **Complete** | `docs/V1.2.md`, `docs/ARCHITECTURE.md`, and `docs/DECISIONS.md` record scope and boundaries. |
| 2 — Shared responsive admin shell | **Complete (local gate)** | Chromium exercised existing journeys, separate Overview/Access control/Security/WireGuard/Statistics pages, keyboard access, and responsive layouts. Overview reports live status for each service and metrics component. |
| 3 — Host metrics collector | **Complete (local and VPS checks)** | Local integration verified isolation/recovery; the VPS collector returned live host memory, disk, network, load, and uptime values from read-only mounts. |
| 4 — Caddy in-flight proxy instrumentation | **Complete (local gate)** | Integration covered concurrent and interrupted transfers, ranges, WebSockets, allowed/blocked requests, and byte accounting against the local Caddy module. |
| 5 — Historical storage and authenticated SSE | **Complete (local and VPS checks)** | Local checks covered authentication, reconnect/expiry, aggregation, retention, update, rollback, and corrupt recovery; populated history remained present after a VPS admin restart. |
| 6 — Statistics UI and browser checks | **Complete (local gate)** | Chromium exercised live/history views and all four ranges, chart bounds, disconnect/reconnect, and responsive/keyboard behavior. |
| 7 — Installer/package integration and release gate | **Local gate and VPS update passed; Windows check pending** | `pwsh -NoProfile -File .\build.ps1 release -Version 1.2.1-dev` passed Go, browser/monitoring, package install/update/rollback checks. The version-matched package is healthy on the test VPS; Windows playback confirmation remains pending. See [TESTING.md](TESTING.md). |

### Authorized administrator UI follow-up — 2026-10-14

- **Status:** Implemented and local gates passed; [PR #40](https://github.com/Mytob/project_j/pull/40)
  merged into `dev` as `4bc5c41`.
- **Changes:** Removed the signed-in pill, administrator-session footer,
  duplicate version/build footer, redundant login caption, Statistics privacy
  note, and bottom return/sign-out link. Version and build remain in Overview's
  Software panel. Access control, Security, and WireGuard now have distinct
  authenticated pages. Overview reports checks for admin, access control,
  Caddy, the WireGuard interface, host metrics, and proxy metrics.
- **Health signals:** Caddy uses its private Unix-socket API; WireGuard writes a
  short-lived interface heartbeat to a named volume mounted read-only by admin;
  collector and proxy status use fresh metrics samples. At that point no Docker
  socket or published health endpoint was added. The separately authorized
  v1.3 container observer follow-up is recorded below.
- **Validation:** `pwsh -NoProfile -File .\build.ps1 test` and
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.2.1-dev` passed; the
  release report is `dist/release-validation-1.2.1-dev.json`. The package was
  installed on the test VPS and its services and public HTTPS endpoints passed
  checks. Native Windows playback after this update remains pending. Full
  command evidence is in [TESTING.md](TESTING.md).

### v1.2 local gate evidence — 2026-10-14

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version 1.2.0-dev`.
- Result: PASS (exit 0). The report at
  `dist/release-validation-1.2.0-dev.json` records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- Source control: feature commit `eaa14f9` was merged into `dev` by PR #37
  (`2cb0d8a`).
- Covered: all Go packages; M1–M6 and v1.1 browser/integration regressions;
  Chromium admin and Statistics workflows; collector container and recovery;
  Caddy live streaming/range/WebSocket metrics; authenticated SSE and
  persistent history; offline package build/load/install, firewall, update,
  preservation, rollback, retention, and password reset.
- At report generation the host checks were blocked because the local run used
  Docker Desktop. Subsequent test-VPS results are recorded below; post-update
  native Windows playback confirmation remains pending.

### v1.2 test VPS deployment — 2026-10-14

- Target: user-authorized Ubuntu 26.04.1 LTS x86_64 VPS serving the configured
  `darkcry.com` hostnames. The existing 1.1.2-dev services were healthy before
  the update and 4.9 GB was available on `/`.
- Command: `./proxyctl-linux-amd64 update
  ./jellyfin-proxy-1.2.0-dev-linux-amd64.tar.gz`.
- Result: PASS. The updater verified the package and existing TOTP storage,
  loaded bundled images without pulls, restarted the Jellyfin Proxy services,
  and reported successful service health and public HTTPS checks. Admin,
  Caddy, hostmetrics, and WireGuard were all healthy afterward.
- Package identity: the archive SHA-256 matched the workstation copy. The
  running admin image reports version `1.2.0-dev`, build
  `62acf66c2182-dirty`. This was built from the tested v1.2 working tree before
  its source commit; create a clean build from merged `dev` before a stable
  release.
- Host metrics: private `GET /metrics` returned live VPS memory, root disk,
  network totals, load averages, and uptime. Docker inspection showed UID
  65532, no added capabilities, no privileged/host PID/network mode, no
  published port, and read-only `/proc`, `/sys`, and root filesystem mounts.
- Public routes with certificate verification enabled: `darkcry.com` 200,
  `admin.darkcry.com` 200, and `access.darkcry.com` 403 with TLS verify result
  0 for each. Anonymous `/statistics` redirected to login; history and SSE
  endpoints returned 401. The access host remained default-deny.
- Persistence and tunnel: TOTP key/state, whitelist files, and site content
  were present after update. A populated daily history file remained present
  across an admin-only restart, and admin returned healthy. The WireGuard
  container reported a recent peer handshake after the full update restart.
- Remaining operator check: confirm Jellyfin streaming from the native
  Windows client after the v1.2 update. The scoped Windows firewall rule and
  streaming were previously operator-confirmed on 1.1.2-dev; the new update's
  peer handshake is observed, but post-update playback was not tested here.

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
| 5 — Privileged VPS CLI recovery | **Complete** | Root-only `reset-totp`, `disable-totp`, and `replace-totp`; replacement is enabled-only and requires a verified new enrollment before normal access returns. Recovery sessions are limited to setup/logout. Focused Go tests and `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-13; [PR #27](https://github.com/Mytob/project_j/pull/27) merged to `dev` as `06805d1`. |
| 6 — Full integration and release testing | **Complete (local gate)** | `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.0-dev` passed on 2026-10-14, including Go, M1–M6 browser/integration, and offline package install/update/rollback. Tests verify TOTP key/state preservation and backup/restore, packaged CLI recovery, downgrade rejection, and package binary permissions. Actual-host v1.1 checks were separate from this local stage. The operator later reported updating the test VPS to 1.1.0-dev and confirmed streaming worked. |

The execution plan follows the supplied implementation brief in order:
standalone engine; auth state/persistence; web enrolment; login enforcement;
root-only VPS CLI recovery; full local integration and release validation.
The Stage 6 host checks were separate from the local gate. The operator later
reported updating the test VPS to v1.1.0-dev and confirmed streaming worked;
the follow-up changes below require their own package validation.

### Authorized operator follow-up — v1.1.1-dev

| Change | Status | Evidence / blocker |
| --- | --- | --- |
| Password-and-TOTP protected admin control to disable TOTP, with global session revocation | **Complete (local release gate)** | Handler tests cover CSRF, wrong password, invalid code, and session revocation; Chromium verifies the end-to-end disable and password-only login in `build.ps1 release -Version 1.1.1-dev`. |
| Show packaged version and source commit build number in the admin dashboard | **Complete (local release gate)** | Browser integration verifies linker-injected metadata; package validation checks image version/revision labels in `build.ps1 release -Version 1.1.1-dev`. |
| Show updater milestone percentage and live activity while long operations run | **Complete (local release gate)** | Focused tests cover progress events and output; `build.ps1 release -Version 1.1.1-dev` passed. Percentage is based on completed milestones; activity continues during wait phases. |

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

#### Stage 6 evidence — 2026-10-14

- `pwsh -NoProfile -File .\build.ps1 package -Version 1.1.0-dev` — PASS.
  The actual release archive installed in an isolated Docker-in-Docker daemon;
  TOTP remained enabled across update, backup/restore retained its encrypted
  state and replay checkpoint, and the packaged `proxyctl` reset/disable/replace
  commands passed. Forced update failure rolled back, a lower-version update
  was rejected before changing active files, retention and failed-install
  cleanup passed, and the unrelated port-conflict container remained running.
- `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.0-dev` — PASS on
  2026-10-14, exit 0. All local Go, M1–M6 integration/browser and M7–M9
  package gates passed. `dist/release-validation-1.1.0-dev.json` records local
  gate `passed` and host-specific checks as blocked.
- The first package attempt exposed missing executable bits on the Linux CLI
  after a Windows-created archive was extracted. The release extractor now
  sets execute permission only on the two known Linux binaries; focused tests
  and the complete package gate passed after the fix.
- No live v1.1 deployment was performed. Public ACME/provider-firewall,
  Ubuntu VPS and native Windows checks remain outside this local stage.

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
| M12 — v1.4 Fail2ban and security management | Local release gate and Ubuntu host restart fix passed; latest native Windows client check not repeated | Clean package `1.4.2-dev` was deployed to the authorized test VPS. Two security-container restarts retained exactly one IPv4/IPv6 SSH rule pair, all six services stayed healthy, a fresh SSH login succeeded, and public TLS routes remained 200/200/403. See [TESTING.md](TESTING.md). |

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

### M12 — v1.4 Fail2ban and security management

- **Status:** Implementation, local release gate, and Ubuntu restart checks
  passed on 1.4.2-dev. The operator-confirmed Windows playback check was on
  1.4.1-dev and was not repeated after this security-only change. No stable
  v1.4 release is claimed.
- **Scope:** Protect SSH authentication and administrator login with isolated
  Fail2ban jails, dedicated IPv4/IPv6 nftables SSH enforcement, signed admin
  authentication events, Caddy-only admin bans, and authenticated admin
  configuration, history, unban, and live updates. Administrator bans do not
  block Jellyfin access.
- **Local gate:** `pwsh -NoProfile -File .\build.ps1 release -Version
  1.4.0-dev` — PASS, exit 0 on 2026-10-17. Go tests, M1–M6 integration,
  three-browser admin checks, isolated Fail2ban/nftables and Caddy enforcement,
  streaming regressions, and offline package install/update/rollback passed.
- **Package:** `dist/jellyfin-proxy-1.4.0-dev-linux-amd64.tar.gz`, SHA-256
  `bfe06b37fc7da19bdf8bef694751c53872c61ef12a87d73843b46111e6656a77`. The
  release report is `dist/release-validation-1.4.0-dev.json` and records
  `local_gate: passed`, `release_readiness: blocked_host_checks_pending`.
- **1.4.1-dev package:** `dist/jellyfin-proxy-1.4.1-dev-linux-amd64.tar.gz`,
  SHA-256 `28006722b800f04a8fe50ad286d27ce0ba09d48c623dbd1b2540c4ecee81efce`,
  built for source revision `418d981f477a`. The local full release gate passed
  on product-identical source before PR #68's test-only merge; a post-merge
  wrapper rerun hit a Playwright screenshot-height mismatch, recorded in
  `docs/TESTING.md` rather than reported as passing.
- **VPS deployment:** `proxyctl update` passed on the authorized Ubuntu VPS.
  Six containers were healthy after update and reboot. The actual host journal
  was readable, two Fail2ban jails were active, reserved IPv4/IPv6 ban/unban
  checks updated the host SSH nftables sets, and the clean post-reboot chain
  contained only the expected TCP/22 rules. Public TLS/DNS returned 200/200/403
  with certificate verification. A 2 GiB swap file is persistent and active.
- **Restart check:** `docker restart jellyfin-proxy-securityd-1` returned the
  container to healthy status. The SSH chain grew from one IPv4/IPv6 TCP/22
  rule pair to two identical pairs. The newly added rules (handles 6 and 7)
  were deleted individually; a fresh SSH login then succeeded, the security
  container remained healthy, and exactly the original pair remained. This
  reproduced the restart bug on 1.4.1-dev.
- **Restart fix:** The Fail2ban nftables startup action now checks for the
  existing table, chain, sets, and per-family rule before adding anything.
  `security-firewall.ps1` simulates abrupt daemon death in a retained network
  namespace and asserts one IPv4/IPv6 TCP/22 rule after restart. The focused
  check, `build.ps1 test`, and `build.ps1 release -Version 1.4.1-dev` passed
  with this working-tree fix; that preliminary package was dirty and is not
  suitable for deployment. The clean `1.4.2-dev` release gate and VPS retest
  passed; details are recorded below and in `docs/TESTING.md`. The operator
  confirmed streaming works on 1.4.1-dev; native Windows playback was not
  repeated on 1.4.2-dev. The generated machine-readable report still marks
  host checks blocked because it predates the VPS evidence. No stable v1.4
  release was published.

- **1.4.2-dev fix package and VPS check:** Clean release gate passed on commit
  `1b1f6ab5d4d8`; package SHA-256 is recorded in `docs/TESTING.md`. The package
  updater completed successfully on the authorized VPS. Two consecutive
  `docker restart jellyfin-proxy-securityd-1` checks each retained exactly one
  IPv4 and one IPv6 TCP/22 drop rule (handles 3 and 5), with both Fail2ban
  jails active. All six containers remained healthy, a new SSH connection
  succeeded, and verified TLS checks returned 200/200/403. The release report
  continues to show host checks blocked because it was generated before
  operator-host evidence was supplied; no stable release was published.

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
| 2026-10-13 | v1.1 Stage 5 root-only TOTP reset, disable and replace commands with restricted recovery enrollment. | [PR #27](https://github.com/Mytob/project_j/pull/27), merged to `dev` as `06805d1` | Focused proxyctl/admin/auth/deployment/TOTP tests, Windows cross-build, and `pwsh -NoProfile -File .\build.ps1 test` — PASS. |
| 2026-10-14 | v1.1 Stage 6 update downgrade guard, package permission fix, full TOTP package and release gate. | [PR #28](https://github.com/Mytob/project_j/pull/28), merged to `dev` as `0e17798` | `pwsh -NoProfile -File .\build.ps1 package -Version 1.1.0-dev` and `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.0-dev` — PASS; local gate passed, production host checks blocked. |
| 2026-10-14 | Responsive TOTP disable form layout and 1.1.2-dev package. | [PR #31](https://github.com/Mytob/project_j/pull/31), merged to `dev` as `8df2ca7` | `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.2-dev` — PASS, exit 0; Go, browser integration, and offline package gates passed. Host-specific checks remain blocked; package not published. |
| 2026-10-14 | Stable 1.1.2 release gate, promotion, and publication. | [PR #33](https://github.com/Mytob/project_j/pull/33) recorded evidence in `dev`; [PR #34](https://github.com/Mytob/project_j/pull/34) promoted `dev` to `main` at `86bf9c2`; tag `v1.1.2`; [GitHub Release](https://github.com/Mytob/project_j/releases/tag/v1.1.2) | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.1.2 -HostCheckEvidence docs/release-host-checks-v1.1.2.json` on `dev` commit `ce3f4e5890e3` — PASS, exit 0, `release_readiness: ready`. Go, M1–M6 Chromium/WireGuard, and M7–M9 offline package/update/rollback/retention checks passed. The stable archive and updater, checksum files, and validation report were uploaded and verified on GitHub. |
| 2026-10-15 | v1.3 React admin, health diagnostics, password change, WireGuard peer lifecycle, and dependency audit. | [PR #43](https://github.com/Mytob/project_j/pull/43), merged to `dev` at `98012d6`; implementation commit `f14737f` | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.0-dev` on commit `f14737f2db83` — PASS, exit 0 at 20:18 UTC. Go, browser/monitoring integration, and isolated offline package install/update/rollback passed. `dist/release-validation-1.3.0-dev.json` records `local_gate: passed`; host checks remain blocked. Dependency scan limits and exact pins are in `docs/DEPENDENCY_AUDIT_V1.3.md`. |
| 2026-10-15 | v1.3 chart interaction, visual regression coverage, three-browser smoke checks, and toolchain audit follow-up. | Commit `693c65d363f4`; [PR #45](https://github.com/Mytob/project_j/pull/45), merged to `dev` at `658e8da`. | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.0-dev` — PASS, exit 0 at 21:14 UTC; Go, Chromium/Firefox/WebKit browser and container integration, and offline package install/update/rollback passed. `dist/release-validation-1.3.0-dev.json` records local gate passed, host checks blocked. Evidence and earlier corrected test failures are in `docs/TESTING.md`. |
| 2026-10-16 | User-authorized Overview simplification, TOTP-protected password changes, one-time WireGuard configuration download confirmation, and restricted container-health observer. | Follow-up on `fix/v1-3-overview-health-followup`; [PR #47](https://github.com/Mytob/project_j/pull/47), merged to `dev` at `f9fed92`. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.0-dev` — PASS, exit 0 at 00:29:52 UTC; Go, frontend, Chromium/Firefox/WebKit browser and monitoring integration, plus offline package install/update/rollback passed. Overview now fits the system summary and compact all-component states into one panel. Report leaves host checks blocked. See [TESTING.md](TESTING.md). |
| 2026-10-16 | v1.3.1-dev test VPS update. | Package built from clean source commit `9e1b7b943805`; product code from [PR #47](https://github.com/Mytob/project_j/pull/47), merged to `dev` at `f9fed92`. | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.1-dev` — PASS, exit 0. `proxyctl update` — PASS on the user-authorized Ubuntu 26.04.1 VPS. Admin, Caddy, containerhealth, hostmetrics, and WireGuard healthy; HTTPS routes returned 200/200/403 with TLS verification. Native Windows WireGuard/firewall/playback checks remain pending. See [TESTING.md](TESTING.md). |
| 2026-10-16 | Require completed one-time WireGuard config download before peer regeneration; deploy `1.3.2-dev` to test VPS. | [PR #50](https://github.com/Mytob/project_j/pull/50), merged to `dev` at `1488ed3`; package built from code commit `b9955bb94501`. | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.2-dev` — PASS, exit 0; Go, three-browser integration, monitoring, offline install/update/rollback and preservation checks passed. VPS update passed; all five containers healthy; HTTPS routes verified 200/200/403 with valid TLS. Native Windows checks remain pending. See [TESTING.md](TESTING.md). |
| 2026-10-16 | Repair one-time WireGuard config deletion permissions and deploy `1.3.3-dev`. | [PR #52](https://github.com/Mytob/project_j/pull/52), merged to `dev` at `fd1114f`; package built from code commit `b8b119d`. | Root cause verified from VPS logs: the admin UID could not remove the config from a root-owned directory. `build.ps1 test` and clean-tree `build.ps1 release -Version 1.3.3-dev` passed, including a regression test that restores the directory to root:65532 group-writable mode. VPS updater passed; pending config preserved for the user to download once. See [TESTING.md](TESTING.md). |
| 2026-10-16 | Dismiss transient WireGuard rotation/download notices after five seconds and deploy `1.3.4-dev` to the test VPS. | [PR #54](https://github.com/Mytob/project_j/pull/54), merged to `dev` at `f8d530a`; package built from clean commit `f8d530a70abf`. | Clean-tree `.\build.ps1 release -Version 1.3.4-dev` — PASS, exit 0; local release gate passed. VPS update passed; all five containers healthy and public HTTPS routes verified 200/200/403 with valid TLS. Native Windows checks remain pending. See [TESTING.md](TESTING.md). |
| 2026-10-17 | Replace Windows peer status and notices with a single state-driven download/regenerate button; deploy `1.3.5-dev` to the test VPS. | [PR #56](https://github.com/Mytob/project_j/pull/56), merged to `dev` at `f4803a4`; package built from clean commit `f4803a4474b1`. | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.5-dev` — PASS, exit 0; local release gate passed. VPS update passed; all five services healthy and public HTTPS routes verified 200/200/403 with TLS verification. Native Windows checks remain pending. See [TESTING.md](TESTING.md). |
| 2026-10-17 | Add optional friendly names to allowed addresses, remove the redundant Jellyfin health-response tile, and deploy `1.3.6-dev` to the test VPS. | Code commit `a8a7937cd68b`; [PR #58](https://github.com/Mytob/project_j/pull/58) into `dev`. | Clean-tree `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.6-dev` — PASS, exit 0; Go, four browser tests, frontend, monitoring/streaming integration, and offline package install/update/rollback passed. VPS updater passed after resolving severe memory pressure with temporary swap; the swap and interrupted-attempt files were removed. All five services healthy, WireGuard handshake recovered, HTTPS routes verified 200/200/403 with TLS verification. The operator subsequently confirmed native Windows playback. The stable 1.3.6 release gate passed with readiness READY and the package was built. PR #63 promoted `dev` to `main` at `659ad83`; GitHub tag and release-asset publication remain pending. See [TESTING.md](TESTING.md). |
| 2026-10-17 | v1.4 Fail2ban and security management implementation. | `feature/v1.4-fail2ban-security`; [PR #66](https://github.com/Mytob/project_j/pull/66) into `dev`. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.4.0-dev` — PASS, exit 0 on synced branch commit `8505699`; Go, M1–M6 integration, four browser tests, isolated Fail2ban/nftables and Caddy checks, and offline package install/update/rollback passed. Report records `local_gate: passed`, host checks blocked. Package SHA-256: `bfe06b37fc7da19bdf8bef694751c53872c61ef12a87d73843b46111e6656a77`. No v1.4 VPS deployment or publication. |
| 2026-10-18 | Deploy v1.4.1-dev, add persistent swap, and exercise Ubuntu host/reboot checks. | Product revision `418d981f477a`; PR #67/#68 already merged to `dev`. | Package SHA-256 verified; `proxyctl update` passed. 2 GiB `/swapfile` persisted through reboot. Six containers healthy; real sshd journal, two Fail2ban jails, IPv4/IPv6 SSH set ban/unban, host nftables chain, and public HTTPS 200/200/403 with valid TLS passed. The operator subsequently confirmed streaming works. A direct security-container restart added a duplicate IPv4/IPv6 SSH rule pair; the extra pair was removed, and a fresh SSH login passed. The fix and repeat-restart retest are recorded in the following entries. See [TESTING.md](TESTING.md). |
| 2026-10-18 | Make Fail2ban SSH rules idempotent across abrupt security-container restarts. | Commit `1b1f6ab5d4d8` on `fix/securityd-nftables-restart-idempotence`; [PR #69](https://github.com/Mytob/project_j/pull/69), merged to `dev` at `eebe308`. | Isolated firewall test asserts one IPv4 and IPv6 SSH drop rule after startup and abrupt Fail2ban restart; full `build.ps1 release -Version 1.4.2-dev` passed. See deployment and two-restart Ubuntu verification below. |
| 2026-10-18 | Deploy the restart fix and verify repeated restarts on Ubuntu. | Package from `1b1f6ab5d4d8`; [PR #69](https://github.com/Mytob/project_j/pull/69), merged to `dev` at `eebe308`. | `proxyctl update` passed. After each of two security-container restarts, the live host nftables chain had exactly one IPv4 and one IPv6 SSH rule; a fresh SSH connection succeeded, all six services were healthy, and public TLS routes returned 200/200/403. |
| 2026-10-19 | Keep the admin session usable after the one-time WireGuard download on mobile browsers; deploy the `1.5.1-dev` follow-up. | Local uncommitted frontend, browser-test, health/UI follow-up. | `pwsh -NoProfile -File .\tests\integration\run.ps1 -UpdateBrowserSnapshots`, `pwsh -NoProfile -File .\build.ps1 test`, and `pwsh -NoProfile -File .\build.ps1 release -Version 1.5.1-dev` — PASS. The authorized VPS updater passed; all six containers healthy with zero restarts, TLS routes returned 200/200/403, both Fail2ban jails active, and SSH nftables had one IPv4 plus one IPv6 rule. No active WireGuard handshake was present at the post-deploy check, so playback and physical iPhone Safari recovery remain unverified on this build. See [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.6 maintenance-job update check on disposable VMware Ubuntu. | `feature/v1.6-fresh-install` at baseline `8562b23`; no commit or PR. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.6 -SupportedUpgradeSources 1.6.0-dev.5` — PASS; `local_gate: passed`, host-dependent readiness blocked. Updated the disposable Ubuntu 26.04.1 guest from dev.5; checksum and `proxyctl doctor` passed. The active maintenance service adopted the updated unit/binary; restricted job API denied root (403), accepted admin UID 65532 (202), completed a backup, retained its job after service restart, and `proxyctl verify-backup` passed. Five containers healthy, local routes 200/200/403. Public ACME/provider networking and native Windows tests remain unverified. No production deployment, merge, or publication. See [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.7 full release gate and clean Ubuntu snapshot-clone acceptance. | `feature/v1.6-fresh-install` at `8562b23` with uncommitted implementation changes; no commit or PR. | `pwsh -NoProfile -File .\build.ps1 test` and `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.7` — PASS. Release report records local gate passed and remaining host checks blocked. On a clone of the VMware `Fresh Install` snapshot, official Docker Engine/Compose prerequisites and the app were installed; checksum, `proxyctl doctor`, five healthy containers, verified backup, local TLS 200/200/403, restricted observer, journald, Fail2ban, IPv4/IPv6 nftables ban/unban, and normal reboot recovery passed. Public ACME/networking and native Windows checks remain unverified; forced interruption and clean-host recovery acceptance remain open. No production VPS deployment, merge, or publication. Package hashes and details are in [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.9 full release gate and exact-package Ubuntu update/rollback acceptance. | `feature/v1.6-fresh-install` at `8562b23` with uncommitted implementation changes; no commit or PR. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.9 -SupportedUpgradeSources 1.6.0-dev.7` — PASS. Exact package checksum verified in disposable Ubuntu clone; update to dev.9, `proxyctl doctor`, rollback to dev.7, both 21-file safety backups, five healthy containers, maintenance service and backup timer all PASS. After rollback, deliberately stopping admin exercised persistent bounded recovery: it returned healthy and doctor passed. Report records local gate passed and host checks blocked. SSH/admin setup, safe unused-image cleanup, forced interruption, clean-host disaster recovery, public ACME/provider networking and native Windows checks remain open. No production VPS deployment, merge, or publication. Package hashes and details are in [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.10 full release gate, Ubuntu update and safe image cleanup acceptance. | `feature/v1.6-fresh-install` at `8562b23` with uncommitted implementation changes; no commit or PR. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.10 -SupportedUpgradeSources 1.6.0-dev.7` — PASS; local release report records host readiness blocked. Exact package checksum and update from dev.7 passed on the disposable Ubuntu clone; doctor, five healthy services, maintenance service and backup timer passed. Maintenance cleanup removed one unused app image and preserved active/rollback references, a stopped-container image and unrelated Docker resources. SSH/admin setup, clean-host recovery, exhaustive forced interruptions, public ACME/provider networking and native Windows checks remain open. No production deployment, merge or publication. Package hashes and details are in [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.11 full release gate and clean Ubuntu SSH administrator check. | `feature/v1.6-fresh-install` at `8562b23` with uncommitted implementation changes; no commit or PR. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.11 -SupportedUpgradeSources 1.6.0-dev.10` — PASS; local release report records host readiness blocked. On a fresh clone, both package checksums verified, Docker/Compose installed, and a password-auth SSH admin passed separate login and sudo checks. A second run enabled `PermitRootLogin no`; a new admin SSH connection and sudo passed, then cleanup restored the original root policy. Five containers reached healthy; app installation correctly rolled back at public HTTPS because the test used `.invalid`. Test account/drop-in and temporary host mappings were removed; Docker remains on the clone. Public DNS/ACME/provider networking, clean-host recovery, forced interruption, and native Windows checks remain unverified. No production deployment, merge, or publication. Package hashes and details are in [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.12 complete disposable Ubuntu recovery acceptance. | `feature/v1.6-fresh-install` at `8562b23` with uncommitted implementation changes; no commit or PR. | The full `build.ps1 release -Version 1.6.0-dev.12 -SupportedUpgradeSources 1.6.0-dev.11` local gate passed; report retains `blocked_host_checks_pending`. On disposable clones, fresh install and `install --resume` after reboot passed; alternate SSH login/sudo and contextual `PermitRootLogin no` passed; update process kills and forced guest reboots at all six durable stages recovered/finalized through `proxyctl repair`; interrupted restore rolled back; manual host updates passed post-health checks without a reboot requirement; a full 16 KiB tmpfs caused a safe backup failure. `proxyctl doctor`, five healthy services, both Fail2ban jails, and the expected SSH nftables table passed. Public DNS/ACME/provider networking and native Windows client checks remain open. No production VPS, original VM, merge, push, or stable release was used. See [TESTING.md](TESTING.md). |
| 2026-10-22 | v1.6.0-dev.13 clean release gate and exact-package Ubuntu update. | Product implementation is PR #71; the release build used merged dev commit 432b0db7bc74. | Full clean-tree release gate passed with local_gate: passed; public/Windows checks remain blocked. The exact package updated the dev.12 disposable Ubuntu clone, passed readiness, retained active/previous releases, and proxyctl doctor passed with build 432b0db7bc74. Package SHA-256 2c72872dbc1cf5f3e100618fe8295e533b1387e1d859231758d09b4b6c9b4e9e; proxyctl SHA-256 db53f20494b826156adf545ab36f88cb80e4f1d70b76f52de947792afb496e6f. No production deployment or stable publication. |
| 2026-10-22 | v1.6.0-dev.15 clean release gate and Ubuntu exact-package update/reboot check. | Clean dev commit `ebd767615ded1abc6fe776a7c229e8c0784c971b`; docs-only PR #77 was merged before the build. | `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.15 -SupportedUpgradeSources 1.6.0-dev.14` — PASS, exit 0; local gate passed and public/Windows host checks remain blocked. Exact package updated the disposable Ubuntu 26.04.1 clone from dev.14; checksum, pre-update backup, all five healthy containers, doctor, verified 21-file backup, maintenance/backup units, actual SSH journal access, Fail2ban, and IPv4/IPv6 nftables ban/unban passed. Normal reboot recovered all five containers and host security state. WireGuard listens, but no peer handshake. Package SHA-256 `ea14fd5864fcde11d45d23031adbb3abf9be2ee1d3a1fe0f0ceb3991be668064`; standalone proxyctl SHA-256 `69bf06d16f5da11a475d5ca8cab6101323c6b78d636997a526ffb883868e4b22`. No public VPS, production deployment, or stable publication. |
