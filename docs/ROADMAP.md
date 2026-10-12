# Implementation roadmap

Status is based on behaviour and recorded test evidence, not file presence.
No milestone is marked complete until its mandatory tests pass.

## Current status

| Milestone | Status | Evidence / blocker |
| --- | --- | --- |
| M1 — Minimal working proxy | Complete | `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-12; see test log below. |
| M2 — Default-deny IP whitelist | Complete | Go unit tests and live Caddy/Docker enforcement passed on 2026-10-12. |
| M3 — Administrator authentication | Complete | PR #3 merged as `0b1b11f`; Go tests and M1–M3 integration passed. |
| M4 — Admin whitelist management | Complete | `pwsh -NoProfile -File .\build.ps1 test` passed on 2026-10-12. |
| M5 — WireGuard connectivity | Complete | Real encrypted tunnel, outage, recovery, and prior integration checks passed on 2026-10-12. |
| M6 — Windows WireGuard configuration | Not Started | Depends on M5. |
| M7 — Self-contained release packages | Not Started | Depends on application and deployment artifacts. |
| M8 — Guided VPS installer | Not Started | Depends on M7. |
| M9 — Updater, recovery, retention | Not Started | Depends on M8. |
| M10 — Full automated release validation | Not Started | Depends on all preceding implementation gates. |
| M11 — Version 1.0.0 release | Not Started | Depends on M10 and actual release permissions. |

Documentation commit `c8aedb7` is on `main`. M1 commits `613ff18` and
`5c7217f` were merged into `dev` through [PR #1](https://github.com/Mytob/project_j/pull/1)
at merge commit `f042820`. M2 commit `5f285cb` was merged through
[PR #2](https://github.com/Mytob/project_j/pull/2) at merge commit `e81e422`.
M3 commit `18c6a96` was merged through
[PR #3](https://github.com/Mytob/project_j/pull/3) at merge commit `0b1b11f`.
M4 commit `7954bfb` was merged through
[PR #4](https://github.com/Mytob/project_j/pull/4) at merge commit `024b7f2`.

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

- **Status:** Not Started
- **Dependencies:** M5.
- **Deliverables:** Key generation, securely retained Windows `.conf`,
  split-tunnel routes, persistent keepalive, and authenticated download.
- **Tests:** Key and peer syntax, permissions, repeat downloads, and
  persistence.
- **Gate:** Generated config is valid and repeatably downloadable.
- **Completion evidence / open issues:** Pending.

### M7 — Self-contained release packages

- **Status:** Not Started
- **Dependencies:** Application and deployment image definitions.
- **Deliverables:** Go builds, pinned Docker image builds and exports,
  versioned manifest, deployment templates, and validated release archive.
- **Tests:** Load the packaged images in a clean Docker environment; validate
  archive contents and package compatibility without registry pulls.
- **Gate:** Package installs and runs without application image registry access.
- **Completion evidence / open issues:** Pending.

### M8 — Guided VPS installer

- **Status:** Not Started
- **Dependencies:** M7.
- **Deliverables:** Native Linux `proxyctl install`, Ubuntu 26.04 x64
  preflight, Docker/Compose detection, DNS guidance and resolution check,
  initial credentials, WireGuard setup, scoped firewall rules, package load,
  deployment, and readiness checks.
- **Tests:** Fresh install and failure-path tests; preserve existing SSH and
  unrelated firewall rules; ensure failed installs do not leave public access.
- **Gate:** Automated fresh-install and failure-path tests pass.
- **Completion evidence / open issues:** Pending. Host-specific tests need
  Ubuntu 26.04.

### M9 — Updater, recovery, and retention

- **Status:** Not Started
- **Dependencies:** M8.
- **Deliverables:** `proxyctl update` and `proxyctl reset-password`, package
  compatibility checks, health verification, rollback, and retention of the
  active and one prior known-good release.
- **Tests:** Update success/failure, rollback, data preservation, release
  retention, restart behaviour, and no global Docker pruning.
- **Gate:** Update and recovery tests pass.
- **Completion evidence / open issues:** Pending.

### M10 — Full automated release validation

- **Status:** Not Started
- **Dependencies:** M1–M9.
- **Deliverables:** Complete `build.ps1 release` runner and implementation of
  all mandatory gates, including explicit host preflight checks.
- **Tests:** Full required suite from the specification; mandatory checks may
  not be silently skipped.
- **Gate:** All locally runnable checks pass; host-only limitations are
  reported and preflighted.
- **Completion evidence / open issues:** Pending.

### M11 — Version 1.0.0 release

- **Status:** Not Started
- **Dependencies:** M10.
- **Deliverables:** Validated promotion from `dev` to `main`, verified release
  commit and tag, official artifacts where permissions allow, install/update
  docs, and automated first-deployment checks.
- **Tests:** All release gates and artifact verification.
- **Gate:** No mandatory failures; no claim of VPS deployment without access.
- **Completion evidence / open issues:** Pending.

## Change and test log

| Date (UTC) | Change | Commit / PR | Tests and result |
| --- | --- | --- | --- |
| 2026-10-12 | Initial repository inspection. | None | Docker Desktop 29.8.2 and Compose 5.6.0 present. WSL access denied; native Go absent. |
| 2026-10-12 | M1 local proxy foundation and verified project tests. | `c8aedb7` (docs); `613ff18` (M1); [PR #1](https://github.com/Mytob/project_j/pull/1), merged as `f042820` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M2 whitelist parser, persistence, Caddy policy, and access tests. | Commit `5f285cb`; [PR #2](https://github.com/Mytob/project_j/pull/2), merged as `e81e422` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M3 password auth, file credentials, sessions, CSRF, throttling, and admin HTTPS integration. | Commit `18c6a96`; [PR #3](https://github.com/Mytob/project_j/pull/3), merged as `0b1b11f` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M4 admin whitelist management, private Caddy Unix API, transaction handling, and persistence. | Commit `7954bfb`; [PR #4](https://github.com/Mytob/project_j/pull/4), merged as `024b7f2` | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
| 2026-10-12 | M5 WireGuard peer, shared network namespace, tunnel outage/recovery integration. | Feature branch / PR pending | `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. |
