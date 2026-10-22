# v1.5 Codebase Audit

**Audit baseline:** `dev` at `8562b23f0da21fe9f6c17f8367a30171b72b635b` (verified equal to GitHub `dev`); working tree was clean before this report. **Date:** 2026-10-18.

## Scope and coverage

The audit followed request paths through frontend, API, persistence, network and deployment code. Generated build products were counted but not manually reviewed as source. The repository contains 176 tracked files:

| Area | Tracked files | Review coverage |
| --- | ---: | --- |
| `cmd/` | 12 | All executable entry points and platform-specific helpers reviewed. |
| `internal/` | 90 | All Go package files and admin React/TypeScript source reviewed; generated frontend placeholder excluded. |
| `deploy/` | 17 | Production Compose, Dockerfiles, Caddy, WireGuard, Fail2ban, security and metrics configuration reviewed. |
| `tests/` | 35 | Test layout, browser journeys, release harness, fixtures and test isolation reviewed; individual assertions relevant to findings traced. |
| `docs/` | 13 | Architecture, decisions, milestone scope, deployment, testing and release instructions compared with source. |
| Packaging and root | 9 | Release/build scripts, module manifests and repository configuration reviewed. |

The code inventory comprises 88 Go files, one Go module, one React 19/TypeScript/Vite admin frontend, 10 server-rendered fallback templates, 17 deployment files and 35 test files. There is no application database or migration system: configuration and credentials use validated files; monitoring history uses bounded JSON/gzip files. No GitHub Actions workflow or hosted CI is present, consistent with project policy. The Go module has three direct requirements and a larger Caddy dependency graph; the frontend has React runtime dependencies and pinned build/test tooling.

### First-party source inventory

- Executables: `cmd/admin`, `cmd/containerhealth`, `cmd/hostmetrics`, `cmd/mock-jellyfin`, `cmd/proxyctl`, `cmd/securityd`, and `cmd/wgcontrol`.
- Domain/adapters: `internal/admin`, `auth`, `caddytelemetry`, `containerhealth`, `deployment`, `monitoring`, `release`, `security`, `totp`, `whitelist`, and `wireguard`.
- Browser UI: `internal/admin/frontend/src/main.tsx`, `metrics.ts`, `security-dashboard.tsx`, their tests, and the two stylesheets. The embedded built UI is served by Go; Node is build/test only.
- Deployment surfaces: `deploy/compose.yaml`, `deploy/{admin,caddy,containerhealth,hostmetrics,security,wireguard,fail2ban,site}` and the integration counterpart under `tests/integration/`.
- Test surfaces: Go package tests; `tests/deployment`; integration runner and Compose fixtures; Chromium, Firefox, WebKit, mobile and desktop browser tests.

## Architecture and end-to-end traces

| Capability | Trace inspected | Result |
| --- | --- | --- |
| Administrator login and TOTP | `cmd/admin` → `internal/admin/server.go` → `internal/auth`, `internal/totp` → protected credential/state files → browser enrollment/login tests | Opaque in-memory sessions, password hashing, TOTP replay protection and CSRF are present. No confirmed authentication bypass found in the reviewed paths. |
| Default-deny access | Admin allowlist handlers → `internal/whitelist` validation/persistence → Caddy transactional config over private Unix socket → Caddy access route | Invalid configuration fails closed; forwarded headers are not used as client identity. Existing integration tests exercise allow/deny and spoofed-forwarding cases. |
| WireGuard peer lifecycle | `internal/wireguard` provisioning/control → persistent server/client configuration → admin one-time config handler → namespace firewall and recovery/update flows | Persistent recovery is tested. The one-time private config is currently retrieved with a state-changing GET; see security report. |
| Proxy telemetry/history | Caddy metrics module → `internal/caddytelemetry` → monitoring feed/history → authenticated SSE and Statistics UI | In-flight byte accounting, bounded subscribers and 90-day bounded file history exist. Historical error-rate aggregation is not request weighted. |
| Host/container monitoring | Read-only host metric mounts → `internal/monitoring`; separate `containerhealth` observer → private admin-only observer network | No collector port is published. The observer has a Docker socket and is the documented exception to the no-socket admin boundary. |
| Security operations | `securityd` → Fail2ban/journald/nftables controller → host firewall | Root and `NET_ADMIN` are limited to the purpose-built security service; tests use isolated host/network fixtures and preserve unrelated rules. |
| Installer/update/recovery | `proxyctl` → package verification/staging → Compose update → health/HTTPS checks and rollback | Persistent configuration/data/site, credentials, keys and previous release are explicitly preserved. Isolated package tests cover install, update, rollback and cleanup. |

## Confirmed findings

Severity uses project-local priority: **P1** release-blocking/high impact, **P2** correctness or security issue requiring this release, **P3** maintainability/quality improvement.

| Priority | Location | Root cause and evidence | Impact / recommendation |
| --- | --- | --- | --- |
| P2 | `internal/monitoring/host.go:readCPU` | `/proc/stat` total sums guest and guest_nice although Linux accounts these inside user/nice. Existing CPU fixture has zero guest counters. | CPU usage is understated when guest time is nonzero. Sum the first eight CPU counters and add nonzero-guest regression coverage. |
| P2 | `internal/monitoring/history.go:aggregateProxy` | `ErrorRatePercent` is averaged as a gauge even though each Caddy sample derives it from interval error/request deltas (`internal/caddytelemetry/metrics.go`). | Quiet and busy intervals receive equal weight, making historical error rates misleading. Aggregate deltas/requests or retain a sufficient weighted numerator and denominator. |
| P2 | `internal/admin/server.go:statisticsEvents`, `componentHealth`; `internal/admin/frontend/src/main.tsx` | Every SSE subscriber evaluates health initially and on a 15-second keepalive; each evaluation calls upstream health sources and persists health state. SPA also polls `/api/initial` every 30 seconds while SSE already carries changing state. | Duplicated probes and durable writes scale with tabs. Share one bounded server sample, skip unchanged persistence, and remove redundant bootstrap polling while retaining reconnect recovery. |
| P2 | `internal/admin/server.go` CPU health calculation | A single host sample at 95% changes state immediately and a sample below the threshold clears it immediately. | Short spikes can flap status and append repetitive history. Add tested consecutive-sample hysteresis and freshness handling; preserve genuine sustained degradation. |
| P2 | `GET /wireguard/config` in `internal/admin/server.go`; `wireguard.html` | A GET consumes/deletes the private peer configuration after response transfer. Cookie policy is Strict, but GET remains a state-changing action without a CSRF token. | Same-site navigation/script can consume the one-time secret and deny the administrator access; response confidentiality remains protected by browser same-origin rules. Use authenticated POST with CSRF and update the React/fallback flows. |
| P2 | `deploy/compose.yaml` admin service | The non-root admin container lacks read-only root filesystem, all-capability drop, `no-new-privileges`, and a bounded writable `/tmp`. | A compromised process has more writable/container privilege than required. Add these controls in production and integration Compose, then exercise startup and writable data paths. |
| P3 | `internal/admin/frontend/src/main.tsx` Overview/Statistics/Health/Security | Overview repeats the full component grid and security summary; Statistics includes host charts and proxy traffic; detailed Health/Security cards repeat headings, badges, timestamps and empty chart space. | Information hierarchy is noisy and the user must scan repeated data. Follow the page restructuring in `DASHBOARD_REDESIGN.md` without dropping capabilities. |
| P3 | `internal/monitoring/history.go`, `internal/admin/frontend/src/main.tsx` | The “Error rate” label sits beside cumulative HTTP error count although the rate is for the latest sampling interval; charts have limited scale/axis context and independent sample selection. | Different time bases are easy to misread. Explicitly label cumulative versus interval values and improve axes, tooltips and synchronized time selection. |
| P3 | `internal/release/image_archive.go`, `internal/release/package.go`, `internal/admin/server_test.go`, `internal/security/manager.go` | Baseline `staticcheck` reported deprecated tar aliases, one unused test helper and a simplifiable loop; remaining findings are error-string capitalization style. | The candidate fixes the safe findings and preserves compatibility with zero-flag regular files. Final scan has only 32 out-of-scope `ST1005` style warnings. |

## Test and maintainability baseline

`go test -cover ./...` passed. Package coverage ranges from `internal/security` 39.9%, `internal/wireguard` 59.4%, `internal/admin` 62.0%, `internal/containerhealth` 65.2%, `internal/auth` 76.0%, to `internal/monitoring` 78.6% and `internal/totp` 89.8%. `cmd/proxyctl` is 23.9%; most other entry points have no direct unit coverage. These figures exclude system integration/browser tests and are not a substitute for them.

The complete existing `build.ps1 test` baseline passed once, including Go, isolated Docker integration and 4 browser tests across Chromium/Firefox/WebKit plus responsive layouts. A separate repeated integration run failed the Chromium TOTP security-page screenshot: expected 1440×3241, rendered 1440×3287, with 4% differing pixels against a 1.5% threshold. This is a baseline determinism/layout issue, not a v1.5 regression. `go vet ./...` passed. `staticcheck@0.8.2 ./...` exited 1 for the findings above. Full evidence and unavailable gates are in [TEST_REPORT.md](TEST_REPORT.md).

## Audit limits

The source and current GitHub development head were inspected. Docker Desktop became unavailable during one resumed audit session; access later recovered for the final local test/release gates and Trivy 0.76 image scans. WSL2 access returned `WSL/E_ACCESSDENIED`, so actual Windows/WSL2 host tests remain blocked. Docker Scout requires Docker account login and was not used. No production VPS testing was performed.

## Candidate follow-up

The v1.5 working tree addresses the confirmed P2 metric, sampling, freshness,
WireGuard download, and admin-container findings listed above. Targeted unit
and integration coverage plus the local release gate passed on 2026-10-18; see
[TEST_REPORT.md](TEST_REPORT.md). The dashboard changes implement the core
page separation and progressive disclosure in
[DASHBOARD_REDESIGN.md](DASHBOARD_REDESIGN.md). The current Trivy image scan is
complete and its distinct HIGH findings are triaged in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md). Static-analysis cleanup is complete
apart from explicitly out-of-scope style warnings. Accessibility review,
comparable performance measurements, actual host tests, and final changed-code
review remain open. This is not yet a completion audit.
