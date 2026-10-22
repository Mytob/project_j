# Jellyfin Proxy v1.6 — Current Codebase Audit

**Audit date:** 2026-10-22

**Baseline commit:** `8562b23` (v1.6 branch start)
**Current tested dev commit:** `78dfb7987946f011e88dc7cde4660c2d24b12142`
**Implementation PR:** #71 merged into dev at c8e279a.
**Documentation PR:** #72 merged into dev at 432b0db.

The original v1.6 branch began with 43 tracked or untracked v1.5 follow-up paths; they were preserved. The v1.6 installer is a fresh-install path and must not migrate v1.5.1 state.

This audit reviewed the current repository structure and the actual command,
package, deployment, authentication, statistics, security-event and proxy
paths. The earlier v1.5 source/security audit in this directory is used as
historical evidence, not as a substitute for these current-source findings.

## Branch-start baseline (historical)

The following source observations and findings describe the branch-start
baseline before the v1.6 implementation work. They are retained as audit
evidence and are superseded where the dated implementation re-audit below
records a later change. Do not read these statements as the current code state.

## Architecture and data flow observed at branch start

- One Go module has distinct `cmd/admin`, `cmd/proxyctl`, `cmd/securityd`,
  `cmd/wgcontrol`, `cmd/hostmetrics`, `cmd/containerhealth` and test/helper
  entry points. Reusable code is under `internal/`.
- Caddy routes the public site from `/srv/site`, the admin hostname to the Go
  admin service, and the access hostname through the custom allowlist and
  in-flight proxy metrics handlers. WireGuard carries the Jellyfin path.
- Administrator credentials are Argon2id password hashes. TOTP state is
  encrypted using a separately stored key; browser sessions are in-memory,
  CSRF-protected and invalidated on process restart. The admin container is
  non-root, read-only, drops capabilities, and uses `no-new-privileges` in the
  current working-tree Compose files.
- Most product state is protected JSON or files: admin/TOTP, whitelist,
  security manager state, signed security-event spools, health history, and
  compressed per-day monitoring samples. There is no application SQLite
  dependency in `go.mod` or use of `database/sql`; the SQLite file configured
  under `deploy/fail2ban/jail.local` belongs to Fail2ban only.
- Proxy history is compressed JSON per day, capped at 90 days by a constant.
  Security history has a configurable duration from one hour to 365 days. The
  dashboard does not offer the six requested retention choices or report
  aggregate application-database storage.
- `cmd/proxyctl` currently accepts `install`, `update`, password recovery and
  TOTP recovery. Install is line-oriented; package and update commands accept
  `.tar.gz`. It validates Ubuntu 26.04 and amd64 before writing, checks DNS,
  asks for domain/password/WireGuard port, and installs only bundled images.
- `internal/release` currently validates a gzip/tar archive, schema 1 manifest,
  file hashes and image identities, path traversal, links, and a 2 GiB
  expanded-size ceiling. `packaging/package.ps1` creates
  `jellyfin-proxy-<version>-linux-amd64.tar.gz` with seven offline images and
  per-file hashes. There is no independently supplied whole-package checksum,
  `.pkg`/`.bak` format, supported-source range, management-tool minimum, or
  database schema declaration.
- `internal/deployment.Install` refuses to overwrite an existing install and
  cleans a failed first install. It has no durable stage journal or resume
  command. `internal/deployment.Update` stages and validates a newer package,
  activates files atomically, waits for container and public HTTPS checks, and
  restores the previous release files on failure. It does not create a
  mandatory pre-update data backup or persist an update stage for crash/reboot
  recovery.
- The `containerhealth` sidecar is separate from admin, but mounts the Docker
  socket. A read-only bind mount does not restrict HTTP methods supported by
  the daemon; compromise of this observer can therefore reach the host Docker
  API. The admin container itself has no Docker socket mount.
- Compose uses Docker restart policies for process resilience. No bounded
  persistent recovery controller, crash-limit policy, or recovery incident
  workflow was found in the application services.
- Existing automated coverage includes Go package tests, browser tests,
  isolated service integration, offline image-load/package install/update/
  rollback checks, and v1.5 release tooling. The current v1.5 report records
  local checks separately from real-host checks. A fresh Ubuntu 26.04.1 clone
  has now run the dev.11 package through Docker/Compose setup, alternate SSH
  administrator verification, container startup, and the public-HTTPS rollback
  path; the public-domain installation gate remains unverified.

## Findings recorded against the branch-start baseline

Severity: **P1** blocks the promised install, recovery or package integrity
boundary; **P2** is a security or correctness gap the v1.6 scope must resolve;
**P3** is a usability or maintainability gap.

| Priority | Evidence | Finding | v1.6 remediation and proof |
| --- | --- | --- | --- |
| P1 | `cmd/proxyctl/main.go`; `internal/deployment/install.go`; `internal/deployment/preflight.go` | The installer is a short line-prompt flow. It does not gather or review SSH, firewall, allowlist, backup, and recovery settings; does not verify alternate SSH access; and cannot resume after reboot. | Build the guided keyboard TUI with masked fields, validation/review, explicit approval for host changes, durable idempotent checkpoints, `install --resume`, and crash/reboot tests. Keep cleanup constrained to files/resources created by this install. |
| P1 | `packaging/package.ps1`; `internal/release/package.go`; `cmd/proxyctl/main.go` | The artifact is `.tar.gz`; the archive's internal manifest hashes files but cannot authenticate the complete archive. Compatibility and schema constraints are absent. | Version `.pkg` and `.bak` formats; require independently supplied SHA-256 before extraction; add strict manifest validation, target/upgrade/schema/tool compatibility, compressed and expanded limits, entry-count limits, checksums and corruption tests. Do not add signing infrastructure. |
| P1 | `internal/deployment/update.go` | Update rollback restores active release configuration but is not preceded by a mandatory verified backup; stage is in memory, so process termination/reboot has no durable resume/rollback decision. | Add a durable transaction journal, required pre-update `.bak`, explicit stage transitions, CLI/dashboard progress, restart recovery and fault injection at each stage. Never proceed if backup validation fails. |
| P1 | Repository-wide search for backup/restore commands found no product `.bak` implementation; `cmd/proxyctl/main.go` has no `backup`, `restore`, or `recover` operation. | There is no product backup, integrity check, restore or disaster recovery path. | Implement owner-only, unencrypted `.bak` files under `/var/backups/jellyfin-proxy`, with authenticated admin download, integrity verification, coordinated state capture, safe restore and fresh-host recovery. Never blindly restore SSH/firewall state. |
| P1 | `go.mod`; `internal/monitoring/history.go`; `internal/security/manager.go` | Product has no SQLite store. Proxy retention is fixed at 90 days; security retention accepts arbitrary 1-hour–365-day durations. | Add a bounded SQLite persistence layer for the selected historical records, online backup support, six exact retention choices defaulting to 30 days, batched pruning, accurate retained totals and storage reporting. Preserve auth/key files outside the DB where appropriate. |
| P2 | `deploy/compose.yaml` `containerhealth` service; `cmd/containerhealth/main.go` | The observer has host Docker API access despite its read-only socket mount; this is broader than its health-reading function. | Put Docker observation and approved mutations behind a host maintenance API with fixed operations, caller authorization, argument/path validation and durable jobs. Remove direct unrestricted socket access from web-facing containers; add negative tests for every unapproved endpoint/action. |
| P2 | `cmd/proxyctl/main.go`; `internal/deployment/docker.go` | No `doctor`/`repair` command or guided manual host-maintenance workflow exists. Initial Docker prerequisite installation is confirmed, but there is no reviewed manual OS/Docker update workflow or report of required reboot. | Add read-only diagnostics and narrowly scoped confirmed repairs. Manual host update mode must preview, confirm, check compatibility/health and report reboot needs; never add unattended upgrades or reboot scheduling. |
| P2 | `deploy/site/index.html`; `deploy/caddy/Caddyfile`; admin routes and templates | Static homepage is a packaged default directory. No validated ZIP upload/staging/atomic publication or public custom 403/404/502/503 page management exists. | Add isolated static ZIP validation, size/count/path/link limits, staging and atomic publish/rollback; render public custom error pages while preserving status codes and keeping admin origins outside that content root. |
| P2 | `deploy/compose.yaml` restart policies; `internal/admin/health_state.go` | Docker restarts a failed process, but no persistent bounded recovery policy/event history distinguishes a crashed internal service from an unavailable external Jellyfin host. | Add capped retries with progressive backoff, persisted attempt state and actionable incidents; do not loop on external endpoint failure. Exercise process crashes and repeated failure recovery. |
| P2 | `internal/admin/frontend/src/main.tsx`; `internal/admin/server.go` | Current dashboard provides existing routes and update information, but does not implement the specified System, Web Content and About workflows, chunked independently-checksummed package upload, retention/storage controls or running component version inventory. | Reorganize the existing UI into the requested destinations without removing essential features; use resumable bounded uploads and operation status from the restricted maintenance job API. |
| P2 | `internal/release/package.go` | Archive extraction rejects traversal, links, duplicate files and mismatched internal hashes, but the 2 GiB limit counts expanded regular-file bytes only. It does not cap compressed input size or the number of archive entries. | Bound input size, file count and metadata, reject malformed/unsupported manifests before filesystem changes, and add archive-bomb/zero-byte-entry tests. |

## Existing controls to preserve

Keep the single Go module, separate executable entry points, in-flight Caddy
traffic accounting, fail-closed allowlist behavior, admin-only statistics and
bounded SSE, Argon2id/TOTP/CSRF/session protections, WireGuard key handling,
Fail2ban SSH/admin enforcement, persistent config separation, offline bundled
images, scoped Compose project behavior, and the v1.5 quality/security
remediations. The new privilege boundary must not grant arbitrary shell or
unrestricted Docker access to the web service. No automatic APT/Docker/app
updates, scheduled reboot, package signature infrastructure, or v1.5.1 data
migration is in scope.

## Audit checks run

- Enumerated source, command, deployment, and documentation files with
  `rg --files`; inspected all `cmd/` entry points, Go module dependencies,
  current package validation/build scripts, install/update code, Compose,
  Caddy routing, auth/session/TOTP, history, security state/events and
  monitoring paths. The earlier v1.5 audit supplies the detailed baseline for
  remaining Go packages and frontend/security review.
- `rg -n "database/sql|sqlite|modernc.org|mattn/go-sqlite3" go.mod cmd internal`
  — no application database matches; the only SQLite reference found in the
  deployment search is Fail2ban's own database file.
- `vmrun getGuestIPAddress 'D:\VM\Ubuntu\Ubuntu 64-bit.vmx' -wait` returned
  `192.168.145.131`. SSH confirmed Ubuntu Server 26.04.1 LTS, x86-64, 2 CPUs,
  5.2 GiB RAM and a 9.8 GiB root disk with 6.3 GiB available. The guest has no
  Docker installation, Jellyfin Proxy files, or existing containers/volumes.
- Local `go test ./...` is unavailable because Go is not on the Windows PATH.
  Docker-backed `go test` for `internal/release`, `internal/deployment`,
  `cmd/proxyctl` and `tests/deployment/installcheck` passed after the package
  changes. The first full `build.ps1 test` run failed at the security
  integration's trusted-client sign-in because it did not receive a CSRF
  token. The test helper now reports the HTTP status and response preview;
  subsequent full `build.ps1 test` and release-gate runs passed.

## v1.6 implementation status

The first implementation slice introduces schema-2 `.pkg` validation,
independent whole-archive SHA-256 enforcement, target/build/source/tool/database
compatibility fields, compressed and expanded size limits, a 10,000-entry cap,
and an explicit rejection of v1.5.1 as an upgrade source. `proxyctl install`
and `update` now ask for the separately sourced checksum and validate the
package before host changes. `packaging/package.ps1` now emits `.pkg`, package
and utility checksum sidecars. The following implementation re-audit
supersedes baseline findings where code has since changed.

## Implementation re-audit — 2026-10-21

The working tree now contains more v1.6 functionality than the initial audit
snapshot above. The original table is preserved as baseline evidence; its
findings must not be read as statements that those features are all still
absent.

### Implemented and exercised in the current tree

- Schema-2 `.pkg` archives validate target/build/upgrade/database/utility
  compatibility, independent archive SHA-256, internal file hashes, path and
  type restrictions, and archive limits. The production images are packaged
  for offline load; stable signing is deliberately excluded.
- `proxyctl` has a keyboard installer, durable install checkpoints and resume,
  package install/update, backup verification, restore, fresh-host disaster
  recovery, doctor/repair,
  manual host update, and password/TOTP recovery commands. The web admin does
  not mount the Docker socket; a restricted maintenance observer is packaged.
  The observer negotiates the daemon/client Docker API range and selects the
  lowest compatible version. On Docker Engine 29.1.3 (API 1.52, minimum 1.44),
  this resolves the former hard-coded API 1.41 failure.
- `.bak` create/verify/restore, automatic backup scheduling, SQLite online
  history storage and configured retention, package update rollback, and
  maintenance components are present in the working tree. The System page can
  start and poll a fixed backup action; job progress/results persist in a
  bounded root-owned store and the restricted Unix-socket API rejects root in
  favor of admin UID 65532.
- Restore now reapplies host UID/GID and restrictive modes to extracted
  config/data trees before restarting services. Regression tests cover the
  whitelist, SQLite history and security-event spool. The release CLI emits
  seven restore milestones, and readiness requires all five managed services.
- The `build.ps1 release -Version 1.6.0-dev.10
  -SupportedUpgradeSources 1.6.0-dev.7` gate passed on 2026-10-22:
  Go, frontend, browser, security/streaming/WireGuard integration, and offline
  install/update/rollback all passed. Two preceding attempts exposed fixed-port
  and stale-fixture assumptions in the integration harness; both were
  corrected before the passing run. The release report is
  `dist/release-validation-1.6.0-dev.10.json`; evidence and limitations are in
  [`../TESTING.md`](../TESTING.md).
- The Ubuntu VMware guest has Docker/Compose and received a fresh v1.6
  candidate installation using local `.localhost` domains and a temporary
  local CA. The final package and utility sidecar checksums passed on the guest.
  The final package's updated maintenance binary was installed and restarted;
  after reboot its enabled service returned five healthy managed-container
  snapshots to UID 65532 and denied root. Both test HTTPS routes returned 200.
  The host SSH journal was readable, both Fail2ban jails recovered, and
  reserved IPv4/IPv6 test bans reached the product nftables sets and were
  removed cleanly. This did not test public ACME, full final-package
  reinstall/update, or a native Windows client. A later restore test initially
  failed twice and safely rolled back; the cause was extracted data retaining
  root ownership. With the ownership fix packaged in the new `proxyctl` binary,
  restoring a `1.6.0-dev.1` backup on the same guest passed service readiness
  and local HTTPS. All five containers were healthy, admin state had the
  expected UID/GID and modes, the transaction journal was removed, and the
  resulting 22-file safety backup passed integrity verification. This was a
  restore-path test, not a full package upgrade or clean-host recovery.

### Material requirements still missing or unverified

| Priority | Current status | Remaining requirement |
| --- | --- | --- |
| P1 | Implemented; all six updater states passed process-kill and guest-reboot recovery on disposable Ubuntu | The updater persists a private, fsynced stage journal and pre-update configuration snapshot; `proxyctl repair` rolls back interrupted stages or finalizes a verified commit. It stops the application before restoring files, restarts and checks the prior release, retains the verified pre-update backup, and protects that backup during pending recovery. Focused Go tests cover journal recovery and retry. Host fault injection verified process termination and forced guest reboot at `prepared`, `stopping`, `replacing`, `starting`, `verifying` and `committing`; `proxyctl repair` plus doctor passed after each. |
| P1 | Implemented; clean install, ready-phase reboot and resume passed on a clean Ubuntu snapshot clone | The full guided installer verified the package and utility checksums, installed approved Docker/Compose prerequisites, created an alternate password-auth administrator and required a separate login/sudo check before restricting root login. A reboot at the durable `ready` checkpoint preserved the installation; `proxyctl install --resume` completed after the clone's local Caddy CA was trusted. Five containers and `proxyctl doctor` passed; fresh administrator login and `sudo -v` passed after reboot. Effective root context reported `PermitRootLogin no`. This used `.localhost` test names and is not evidence of public ACME. |
| P1 | Clean-host recovery passed on dev.12; interrupted restore recovered on disposable Ubuntu | `proxyctl recover <package> <backup>` validates a compatible `.bak`, restores static site, integrity-checked statistics and authenticated security events, and keeps freshly generated admin/TOTP/WireGuard/allowlist/host identity. Recovery from a dev.11 backup succeeded on a clean clone using dev.12. A separate restore of a verified 21-file dev.12 backup was process-killed at journal state `replacing`; the persisted journal was observed and `proxyctl repair` restored the prior stack. Five services and `proxyctl doctor` passed afterward. |
| P1 | Implemented locally; browser and offline package gates pass | System dashboard supports backup creation/download/restore, resumable independently-checksummed package upload, compatibility review, update, rollback and durable job progress. Actual destructive dashboard restore/update/rollback on a fresh Ubuntu host has not been accepted end to end. |
| P2 | Implemented locally; browser/integration coverage present | Web Content ZIP upload uses strict archive/path/size limits, staging and atomic publication with one-version rollback; supported error pages are served from the public site root and the admin origin remains separate. Verify custom error status behavior again in the final release gate. |
| P2 | Implemented locally; actual runtime inventory verified through VM observer | About page reports application/build, install date and restricted host/container component versions. The observer reports host inventory only through the authorized maintenance Unix socket. |
| P2 | Implemented; focused tests and disposable-VM fault check passed | The maintenance service uses a fixed five-service allowlist, Docker-observed failure states, persisted retry/backoff limits and bounded recovery events. On the disposable Ubuntu clone, `docker stop jellyfin-proxy-admin-1` was followed by `restart_requested`/`restart_sent` in the recovery record; the admin container returned healthy and `proxyctl doctor` passed. The recorded attempt count included prior recovery history, so this was not a clean retry-limit test. |
| P2 | Disposable Ubuntu 26.04.1 install, update, rollback, recovery and maintenance checks passed | Host journal access, Fail2ban jails, IPv4/IPv6 nftables, reboot, doctor, container health, local TLS, automatic backups, maintenance service, package cleanup, host update, and privilege boundaries passed. A full 16 KiB tmpfs produced the expected backup `no space left on device` failure without affecting the install; doctor still passed. Public DNS/ACME/provider networking and native Windows checks remain unverified. |
| P2 | Blocked | Public DNS/provider firewall, trusted ACME issuance/renewal and internet WireGuard to the Windows Jellyfin host. The dev.7 and earlier clean-VM checks used local `.localhost` domains and a test CA; the dev.11 run deliberately used a reserved `.invalid` name and observed the expected public-HTTPS rollback. Do not use the production VPS/domain for destructive tests. |
| P2 | Blocked | Native Windows WireGuard import/firewall/playback on a Windows 11 test endpoint. |
| P2 | Implemented; focused tests, package gate, and disposable VM check passed | The fixed maintenance `cleanup` action considers only application-labeled Jellyfin Proxy images, keeps references used by active and rollback manifests, and checks all containers, including stopped containers, before deleting an image. It uses non-forced image removal and never invokes broad prune. Focused tests cover unrelated tags/resources; on the disposable Ubuntu clone the action removed one unused test image while preserving active/rollback image references, an image used by a stopped container, and an unrelated image/container. |

### Corrections to baseline evidence

- The VM is no longer in its initial state: Docker Engine 29.1.3 and Compose
  2.40.3 were installed for testing. It remains a private NAT Ubuntu 26.04.1
  guest with 2 CPUs, 5.2 GiB RAM, a 9.8 GiB root filesystem and no swap.
- The successful local release report means only local gates passed. It does
  not mean every v1.6 deliverable or host-specific check is complete. PR #71
  merged the implementation into `dev` at `c8e279a`; no stable release or
  production deployment is claimed. The clean-tree dev.13 release gate later passed after Docker Desktop Linux engine access was restored.

### Maintenance backup-job and update-unit verification — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.6
  -SupportedUpgradeSources 1.6.0-dev.5` — PASS. The package SHA-256 is
  `85d6e0d6551089227e91edfd859650f274f421211344043edb0956626fb2b273`.
  The report records the local gate as passed and host-dependent release
  readiness as blocked.
- The disposable VMware guest updated from `1.6.0-dev.5`; checksum verification,
  pre/post-update `proxyctl doctor`, app health, and local TLS route checks
  passed. The unit-change path now invokes the just-installed proxyctl to
  reconcile its templates, and an active maintenance process is restarted to
  apply a changed unit. This creates systemd's persistent state path and loads
  the current maintenance executable after an update.
- `systemctl status` showed the dev.6 maintenance binary active. The unit has
  `StateDirectory=jellyfin-proxy-maintenance`, mode `0700`, and a private
  writable backup directory. The state and job directories are root-owned
  `0700`; the socket is root:65532 mode `0660` under a root:65532 mode `0750`
  runtime directory.
- Root received HTTP 403 from `/system/jobs`; UID 65532 received 200, started a
  backup job with the sole allowed action, and saw it complete at step 2/2.
  The completed job survived a maintenance-service restart. Its root-owned
  mode-0600 JSON record was present, `/system/backups` listed its archive, and
  `proxyctl verify-backup` verified the 22-file backup.
- All five containers were running and healthy with zero restarts. Guest-local
  static/admin/access TLS responses were 200/200/403 with certificate
  verification result 0. The private container observer returned five healthy
  snapshots to UID 65532.
- This does not close v1.6: SSH alternate-administrator setup, clean-host
  disaster recovery, and mandatory forced-interruption coverage remain open.
  Bounded service recovery was implemented later and is checked below. Public
  ACME/provider networking and native Windows checks remain unverified. No
  production VPS deployment or stable release was made.

### v1.6.0-dev.10 package and image cleanup acceptance — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.10
  -SupportedUpgradeSources 1.6.0-dev.7` passed; its report records local gates
  passed and host readiness blocked.
- The exact package checksum was accepted by the updater on the disposable
  Ubuntu 26.04.1 clone. Update from dev.7 to dev.10, the mandatory pre-update
  backup, and service/local HTTPS readiness passed.
- The fixed cleanup action was invoked through the maintenance Unix socket as
  UID 65532. It removed one unused application-labeled test image and retained
  one such image referenced by a stopped container. All five active and five
  rollback image references remained available, as did an unrelated test
  image and stopped container. The fixture and uploaded package/updater were
  removed after verification.
- After cleanup, `proxyctl doctor` passed, all five application containers
  were running/healthy, and the maintenance service and backup timer were
  active. Public ACME/provider ingress, native Windows, SSH alternate-admin
  setup, clean-host recovery and exhaustive interruption/resume scenarios
  remain unverified. No production VPS was changed, and no release was
  published.

### Docker API compatibility and actual-host observer check — 2026-10-22

- The first installed observer check returned 503. Docker Engine 29.1.3
  reported `ApiVersion: 1.52` and `MinAPIVersion: 1.44`; a direct versioned
  request at 1.41 returned HTTP 400, while 1.44 returned HTTP 200. This was a
  compatibility defect, not a UI or tunnel-health issue.
- `internal/containerhealth/observer.go` now reads `/version`, validates the
  daemon's advertised range, and selects the lowest API version in the
  client/daemon intersection. Unit tests cover legacy 1.41, daemon minimum
  1.44, unsupported ranges, filtered GET requests and data minimization.
  Focused `internal/containerhealth` and `internal/maintenance` tests passed.
- After the complete local release gate passed, the rebuilt maintenance
  executable was copied from the verified `.pkg` and restarted on the VM. The
  restricted endpoint reported all five application containers running and
  healthy with zero restarts; UID 65532 received HTTP 200 and root received
  HTTP 403. The same checks passed after reboot. The final `1.6.0-dev` package
  was not reapplied because it was already active. A separate test-only
  `1.6.0-dev.1` package was used to exercise the updater; it is not a release
  artifact and must not be distributed.

### Update recovery follow-up — 2026-10-22

- `internal/deployment/update.go` now persists update stages and a durable
  rollback snapshot before stopping the stack. Recovery validates the journal,
  snapshot and retained previous release; it then restores the previous
  configuration, reapplies the prior maintenance schedule, restarts the stack,
  and keeps the recovery journal and backup when any step fails.
- `proxyctl repair` detects and attempts this fixed recovery operation before
  ordinary service repair. `doctor` reports a pending update journal. Starting
  a subsequent update also resolves any prior transaction first.
- Backup housekeeping protects the backup named by an active update journal.
- `proxyctl recover <package> <backup>` now restores only portable site,
  statistics and verifiable security-event state during a fresh install. It
  preserves the new credentials, TOTP enrollment key, WireGuard peer keys,
  allowlist and host configuration; it explicitly refuses v1.5.1 backups.
- Focused Go tests and the third `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.6.0-dev` run passed after fixing fixed-port selection and stale
  test-credential cleanup. The report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`; the package and utility
  checksums were also verified on the disposable Ubuntu guest. See
  `docs/TESTING.md` for the exact gate evidence and hashes.

### v1.6.0-dev.9 release gate and exact Ubuntu update/rollback — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.9
  -SupportedUpgradeSources 1.6.0-dev.7` passed. It ran Go, frontend,
  Chromium/Firefox/WebKit browser, M1–M6 integration, security/streaming/
  WireGuard and offline install/update/rollback/retention/recovery checks. The
  report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- Package SHA-256:
  `5da7f7fc90c975ca9d6b38f8361c8fc703eb210781325ad7863e695bef8eb1d9`;
  standalone proxyctl SHA-256:
  `fdfbe8834064619b38f8ca081189153f9e51f50c106cbe2b7d2f5e6df6028ab3`.
- The dev.9 checksum was verified in the disposable Ubuntu guest. The actual
  CLI update to dev.9 passed and retained dev.7; `proxyctl doctor` passed. The
  supported rollback returned to dev.7 with service and local HTTPS readiness.
  The pre-update and pre-rollback backups each passed verification with 21
  files. After rollback, doctor passed, all five product containers were
  healthy, and the maintenance service and backup timer were active.
- This confirms a package update and rollback on the tested VM; it does not
  cover a public HTTPS certificate, public provider firewall, Windows client,
  fresh dev.9 installation, or fault-injected interruption. The release is
  still blocked by the requirements in the table above. No production VPS was
  used.

### Bounded service recovery fault check — 2026-10-22

- On the disposable Ubuntu clone, the admin container was deliberately stopped
  with Docker. The persistent maintenance controller recorded
  `restart_requested` followed by `restart_sent`; the container returned to
  `running/healthy` within about 22 seconds. The other four application
  containers remained healthy, and `proxyctl doctor` passed.
- The recovery state already contained prior events and a nonzero attempt
  count, so this verifies one crash/restart/readiness cycle, not the fresh
  retry limit or progressive backoff thresholds. The original VM and
  production VPS were not modified.

### Actual Ubuntu update and reboot acceptance — 2026-10-22

- The disposable VM had the v1.6 candidate freshly installed using local-only
  domains and a locally trusted Caddy CA. No public DNS or provider firewall
  was used. The OS was Ubuntu Server 26.04.1; Docker Engine and Compose were
  already present, so prerequisite installation is not covered by this run.
- The test-only update package first failed compatibility validation because
  it did not list the installed source version; the updater made no changes.
  After packaging the test candidate with the explicit compatible source,
  one update rolled back when the test client's temporary CA trust was not
  available to the update process. Retrying with the test-only CA bundle
  completed the update and retained the previous release. `proxyctl
  verify-backup` verified the mandatory pre-update backup (21 files), and
  `proxyctl doctor` passed the installed-release, Compose, services, recovery,
  Docker, storage and backup checks.
- Before and after a normal guest reboot, all five product containers were
  `running/healthy`; the maintenance service and backup timer were active;
  local HTTPS returned 200 for the static and admin sites and the expected
  403 for the default-deny access site. The maintenance API denied root (403)
  and allowed only the admin service UID (200). Both Fail2ban jails and the
  product nftables table returned after reboot. SSH failure records from the
  test client were present in security history and host journal, including
  OpenSSH's `sshd-session` records.
- Public DNS/provider ingress/ACME, native Windows WireGuard and firewall,
  clean-host disaster recovery, and forced interruption at every update stage
  remain release blockers. No
  production VPS was used.

### v1.6.0-dev.7 release and clean Ubuntu install acceptance — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 test` and
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.7` both
  passed. The release gate includes Go, frontend, Chromium/Firefox/WebKit
  browser checks, M1–M6 integration, security/streaming/WireGuard regressions,
  and offline install/update/rollback/retention/recovery checks. The package
  report generated at gate time records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- The test used an untouched clone of the VMware `Fresh Install` snapshot at
  `D:\VM\Ubuntu-v1.6-fresh\Ubuntu 64-bit.vmx`; the original VM was preserved.
  The guest was Ubuntu Server 26.04.1 at `192.168.145.135`, with no existing
  app state, Docker or Compose. Package and utility checksum sidecars verified
  on the guest. The official Docker Engine/Compose APT prerequisite path was
  approved and completed, then the dev.7 package installed successfully with
  local-only `.localhost` hostnames. The first install attempt safely rolled
  back because the local test CA was not yet trusted; adding that CA to the
  guest trust store allowed the retry to complete. This was test-certificate
  setup, not public ACME validation.
- `proxyctl doctor` passed, all five application containers were healthy, the
  maintenance service and backup timer were active, and a backup passed
  `proxyctl verify-backup` with 21 files. The restricted observer returned
  HTTP 200 to UID 65532 and HTTP 403 to root. Host sshd journal entries were
  readable; `jp-admin` and `jp-ssh` jails were active. Reserved documentation
  IPv4 and IPv6 ban/unban checks updated and emptied the host nftables sets.
- After a normal reboot, all five containers remained healthy; maintenance,
  backup scheduling, Fail2ban, nftables and observer authorization recovered;
  `proxyctl doctor` still passed. Guest-local base/admin/access TLS responses
  were 200/200/403 with certificate verification result 0.
- Not tested: public DNS/provider firewall/ACME, internet WireGuard to a
  Windows Jellyfin server, native Windows import/firewall/playback,
  clean-host disaster recovery, and force-termination/reboot injection at
  every update/restore stage. The full final-package dashboard mutation flow
  has local browser and offline package coverage, but has not been exercised
  through a real public browser session on this VM. No production VPS or
  public domain was touched; no merge or publication occurred. See
  [`../TESTING.md`](../TESTING.md) for package hashes and detailed results.

### v1.6.0-dev.11 release gate and clean-guest SSH check — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.11
  -SupportedUpgradeSources 1.6.0-dev.10` passed the full local release gate;
  the report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- On a new clone of the `Fresh Install` snapshot at
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx`, the dev.11 package and utility
  sidecars both verified with `sha256sum -c`. Docker Engine and Compose were
  installed from the approved official repository path after a transient
  Ubuntu mirror-sync error was resolved by using the canonical archive in the
  clone. Public DNS was not touched; three reserved `.invalid` names resolved
  to the guest only through its temporary `/etc/hosts` entries.
- `proxyctl install` configured the password-auth SSH administrator. A fresh,
  independent SSH session authenticated as that user, and `sudo -v` succeeded.
  Effective `sshd -T` output showed the account-specific password method and
  retained the existing root `prohibit-password` setting in the first run;
  public-key authentication was not tested here.
- A second run selected root-login disablement after the SSH/sudo check.
  Effective policy changed to `PermitRootLogin no`; a new SSH session as the
  dedicated user and a fresh sudo check succeeded. Cleanup removed the test
  account/drop-in and restored the clone's original root policy.
- The installation started all five product containers and each reported
  `healthy`. The final HTTPS readiness check then failed, as expected, because
  Let's Encrypt rejected `.invalid` and the domain had no publicly trusted
  certificate. `proxyctl` rolled the application back: no project containers
  or `/opt/jellyfin-proxy` remained. The test account/drop-in and temporary
  hostname/source changes were removed; `sshd -t` passed and root SSH policy
  remained unchanged. Docker remains installed in the disposable clone.
- This verifies the host Docker prerequisite path, alternate SSH login/sudo,
  the optional root-login restriction, container startup, and application
  rollback. It is not evidence of successful
  public HTTPS or a complete public-domain installation. The original VM and
  production VPS/domain were untouched. See [`../TESTING.md`](../TESTING.md).

### v1.6.0-dev.12 release gate, recovery and updater interruption acceptance — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.12
  -SupportedUpgradeSources 1.6.0-dev.11` passed the complete local release
  gate. Package SHA-256 is
  `f5262ded5603f7a02f21edd6d1e5472a9c081371a3c08d853e7f6ec9dc4f2df3`; the
  utility SHA-256 is
  `7c3f2b9b369fda01e04ca4bd5f23cc1f8b8f3c9ac2449eb47eecd50e7627786c`.
  The generated report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`. Build ID is
  `8562b23f0da2-dirty`; this is not a clean release artifact.
- The first clean-host recovery attempt rejected a valid backup because it
  counted `admin-writer.health` as an event while `ReadSpool` correctly ignored
  that non-JSON heartbeat. The code now counts signed event JSON separately,
  permits only a safe heartbeat marker and skips that marker during restore.
  The regression test writes the marker alongside a signed event. Focused
  deployment/security tests and the full local release gate passed after the
  fix.
- On the clean disposable clone
  `D:\VM\Ubuntu-v1.6-recovery\Ubuntu 64-bit.vmx` (Ubuntu 26.04.1,
  `192.168.145.137`), package, utility and checksum verification passed. The
  dev.11 recovery backup verified as 21 files. `proxyctl recover` completed
  using test-only `.localhost` hostnames and a guest-local CA, after a separate
  SSH login and sudo check for the new administrator. All five containers were
  healthy; `proxyctl doctor` passed; base/admin/access TLS was 200/200/403 with
  verification result 0. The recovery restored site files and the statistics
  database while generating new credentials, TOTP state, WireGuard material,
  allowlist and host configuration.
- The security daemon read actual host `ssh.service` journal records. Its full
  health check passed. Reserved IPv4 and IPv6 SSH test bans appeared in the
  host `inet jp_fail2ban` sets; unban removed them. The maintenance service and
  backup timer were active. After a normal guest reboot, all five containers,
  `proxyctl doctor`, both systemd units, host journal access, nftables rules
  and 200/200/403 TLS routes passed again.
- On the separate dev.11 clone
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` (`192.168.145.136`), the exact
  dev.12 package updated successfully, created a verified 21-file pre-update
  backup and passed container/HTTPS readiness. All five containers were
  healthy and `proxyctl doctor` passed. An explicit rollback to dev.11 also
  completed and passed HTTPS readiness. Then four forced process interruptions
  were triggered at journal states `prepared`, `replacing`, `starting` and
  `verifying`. After each, `proxyctl repair` recovered the prior healthy
  release; a doctor check after the `replacing` recovery passed. A final
  dev.11-to-dev.12 update completed successfully. The `stopping` and
  `committing` states, reboot interruption at each update stage, interrupted
  install/restore, public DNS/ACME/provider firewall, and native Windows
  WireGuard/firewall/playback remain unverified.
- Only the two disposable VMware clones were used. The original VM and
  production VPS/domain were not touched. No merge or GitHub publication
  occurred. See [`../TESTING.md`](../TESTING.md) for command results and
  complete evidence.

### Fresh install, recovery, storage failure and manual host update — 2026-10-22

- A linked test clone was created from the original VM's `Fresh Install`
  snapshot at `D:\VM\Ubuntu-v1.6-install-interruption\Ubuntu 64-bit.vmx`.
  The original VM was not changed. The dev.12 package and standalone utility
  checksums passed; the guided installer installed approved Docker/Compose
  prerequisites, created an alternate SSH administrator, and confirmed its
  separate login and `sudo -v` before applying root-login restrictions.
- The installer was force-rebooted at checkpoint `ready`. After reboot, the
  checkpoint and five healthy containers remained; `proxyctl install
  --resume` completed using a guest-local trusted Caddy CA for `.localhost`
  test names. Doctor, post-reboot administrator login and sudo passed; the
  effective root SSH configuration was `PermitRootLogin no`.
- A verified 21-file backup restore was process-killed at journal state
  `replacing`. The journal persisted, `proxyctl repair` rolled back to the
  previous stack, and doctor passed. A filled 16 KiB tmpfs separately caused
  the expected backup write failure without consuming root filesystem space
  or harming the application; doctor passed after the mount was removed.
- The manual host-update preview identified 35 upgrades (one package was
  deferred by phasing). After approval, Docker and application health checks
  passed and the host reported no reboot required. Doctor passed afterward;
  the Fail2ban container exposed both `jp-ssh` and `jp-admin` jails, and the
  host retained the expected IPv4/IPv6 SSH nftables rules.
- These checks used a private VMware NAT clone and local `.localhost` TLS.
  They do not establish public DNS, provider firewall behavior, public ACME,
  internet WireGuard or native Windows playback. No production VPS/domain or
  original VM was used. See [`../TESTING.md`](../TESTING.md) for the complete
  command and result record.

### v1.6.0-dev.13 clean-tree release gate and exact Ubuntu update — 2026-10-22

- The clean dev checkout at 432b0db7bc7429f0daa2de83ccfd1b219cffb654 passed
  pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.13
  -SupportedUpgradeSources 1.6.0-dev.12. Go,
  integration/security/streaming, four browser checks, frontend validation and
  offline package gates passed. The report records local_gate: passed and
  release_readiness: blocked_host_checks_pending.
- Package: 137,276,733 bytes; SHA-256
  2c72872dbc1cf5f3e100618fe8295e533b1387e1d859231758d09b4b6c9b4e9e.
  Standalone utility: 14,303,392 bytes; SHA-256
  db53f20494b826156adf545ab36f88cb80e4f1d70b76f52de947792afb496e6f. Both are
  generated locally under dist; neither is committed.
- On the disposable Ubuntu 26.04.1 clone
  D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx (192.168.145.136), the transferred
  package checksum passed. The proxyctl updater completed from dev.12 to
  dev.13, created its pre-update backup, loaded its bundled images, passed
  readiness, and retained both active and previous releases.
- The subsequent proxyctl doctor exited 0. It passed installation layout,
  release metadata (version 1.6.0-dev.13, build 432b0db7bc74), Compose
  configuration, all five application services, restore/update recovery
  journals, Docker Engine, Compose, and host storage.
- The full Ubuntu install/resume/recovery/update interruption/rollback/low-
  disk/host-maintenance matrix was run against dev.12 before this exact-package
  dev.13 update. It was not repeated against dev.13. No production VPS/domain
  was touched. Public DNS, provider firewall, public ACME, internet WireGuard,
  and native Windows client/firewall/playback checks remain blocked; no stable
  release or GitHub release is claimed.

### v1.6.0-dev.14 clean-tree gate and Ubuntu update/rollback/update — 2026-10-22

- The clean dev checkout at `78dfb7987946f011e88dc7cde4660c2d24b12142` passed
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.14
  -SupportedUpgradeSources 1.6.0-dev.13`. The report records local gates
  passed and host-specific release readiness blocked.
- Package SHA-256:
  `20bacf089d92b4d71b87333004b1f72c83397e5832d0326d8da7c21dbf553601`;
  standalone utility SHA-256:
  `9f79399ff2abfac87e70807582db64d44be4791070f64d98d507d5b814bee719`.
- On the disposable Ubuntu clone, the exact package checksum passed. Update
  from dev.13 to dev.14 and subsequent rollback to dev.13 created safety
  backups and passed their release/health checks; re-updating to dev.14
  also passed. The final `proxyctl doctor` passed and reported build
  `78dfb7987946`. All five managed containers were healthy, and the maintenance
  service and scheduled backup timer were active.
- On the final dev.14 installation, the restricted security container read
  host sshd journal entries, reported `jp-admin` and `jp-ssh`, and its host
  nftables chain showed the IPv4 and IPv6 TCP/22 rules. Reserved documentation
  IPv4 and IPv6 addresses were banned/unbanned, leaving zero active bans. The
  WireGuard interface listened on UDP/51820 with its configured peer, but no
  handshake was recorded.
- A separate clone of the clean Ubuntu 26.04.1 snapshot passed the dev.14
  fresh install. Package and sidecar checksums passed; the installer completed
  with isolated `.localhost` names and test-only local CA trust for HTTPS
  readiness. `proxyctl doctor`, five-container health, maintenance service,
  backup timer and verified 21-file backup passed. TLS returned 200/200/403
  for site/admin/access. The restricted container observer returned five
  healthy containers to its authorized UID and 403 to root. Fail2ban, host
  journal access and both SSH nftables address-family rules passed, including
  ban/unban probes. These checks survived a normal reboot. Stopping the admin
  container triggered bounded restart recovery; it returned healthy and
  `proxyctl doctor` passed afterward.
- The full destructive Ubuntu matrix remains the earlier dev.12 evidence; it
  was not repeated against dev.14. Public DNS/provider firewall/ACME, internet
  WireGuard/playback and native Windows client/firewall checks remain
  unverified. The production VPS was not changed. The user-specified
  `D:\VM\Ubuntu` VM was read-only inspected at dev.6 and left unchanged; no
  WireGuard handshake or traffic was observed. No stable release or GitHub
  release is claimed. See
  [`../TESTING.md`](../TESTING.md) for command and result details.

### v1.6.0-dev.15 clean-tree gate and Ubuntu update/reboot — 2026-10-22

- The clean dev checkout at `ebd767615ded1abc6fe776a7c229e8c0784c971b` passed
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.15
  -SupportedUpgradeSources 1.6.0-dev.14`. The report records local gates
  passed and public/Windows host-specific release readiness blocked.
- Package SHA-256:
  `ea14fd5864fcde11d45d23031adbb3abf9be2ee1d3a1fe0f0ceb3991be668064`;
  standalone `proxyctl` SHA-256:
  `69bf06d16f5da11a475d5ca8cab6101323c6b78d636997a526ffb883868e4b22`.
- The exact package updated the disposable Ubuntu 26.04.1 clone from dev.14,
  created its pre-update backup, loaded images, passed readiness, and retained
  active/previous releases. Doctor passed with version dev.15/build
  `ebd767615ded`. All five containers were healthy; the maintenance service and
  backup timer were active; a manual 21-file backup verified.
- The restricted security container read actual host sshd records and reported
  `jp-admin` and `jp-ssh`. The host SSH nftables chain contained one TCP/22
  drop rule for each address family. Reserved documentation IPs were banned
  and unbanned successfully, leaving both sets empty and zero active bans.
  After normal reboot, doctor, container health, backup/maintenance units,
  journal access, Fail2ban and the exact nftables rules recovered. WireGuard
  listened on UDP/51820, but no peer handshake was recorded.
- The full destructive Ubuntu matrix is still the dev.12 evidence and was not
  repeated against dev.15. Public DNS/provider firewall/ACME, internet
  WireGuard/playback and native Windows client/firewall checks remain
  unverified. No production VPS or stable release was used. See
  [`../TESTING.md`](../TESTING.md) for exact package and command evidence.

### v1.6.0-dev.17 maintenance self-restart fix — 2026-10-22

- A dashboard update previously restarted the restricted maintenance systemd
  service from inside its own job process. The restart could terminate the
  updater before the dashboard received durable terminal job state.
- The dashboard path now updates the service definition without restarting the
  active worker, persists the job's terminal state, then schedules a bounded,
  job-ID-named systemd refresh. CLI maintenance retains immediate service
  refresh behavior. Update, rollback, restore and interrupted-update recovery
  pass the deferred-refresh signal through their deployment paths.
- Focused Go tests and the clean dev.17 `build.ps1 release` gate passed. The
  exact package updated a disposable Ubuntu 26.04.1 guest from dev.14 via CLI;
  package checksum, pre-update backup, all five healthy containers, `proxyctl
  doctor`, and the maintenance binary version passed. A delayed systemd-run
  refresh changed the service invocation ID and the post-refresh doctor and
  container checks passed.
- The authenticated dashboard update/rollback flow has not yet been repeated
  on the VM because the test browser session expired and needs a fresh admin
  sign-in. Public provider/DNS/ACME and Windows client checks remain pending;
  the production VPS was not touched. The change is draft PR #79 into `dev`.
