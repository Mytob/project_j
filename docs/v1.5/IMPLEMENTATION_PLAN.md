# v1.5 Implementation Plan

**Base:** verified `dev` commit `8562b23f0da21fe9f6c17f8367a30171b72b635b`. The audit and design documents are the Phase A/B deliverable. Implementation belongs on `feature/v1.5-quality-hardening`; do not merge or deploy without user approval and passing gates.

## Candidate implementation state — 2026-10-18

- Priorities 1–4 are implemented with focused tests: CPU guest accounting,
  weighted historical error rates, shared/fresh health sampling and CPU
  hysteresis, CSRF-protected one-time WireGuard POST, and admin container
  hardening.
- Priority 5's core six-page reorganization is implemented and passed the
  desktop/mobile, Chromium/Firefox/WebKit browser gate. Formal accessibility
  checks remain open.
- Priority 6's safe cleanup is complete: the deprecated tar aliases, unused
  test helper and append loop were fixed with legacy archive compatibility
  coverage. The fallback disk bar no longer requires inline styles and CSP is
  restricted to same-origin styles. Final staticcheck still exits 1 on 32
  unrelated `ST1005` capitalization warnings, which the v1.5 brief excludes.
- Priority 7's current Trivy 0.76.0 scan and distinct HIGH/CRITICAL triage are
  complete for the candidate images. The security image contains 13 distinct
  HIGH CVEs with Debian Trixie no-DSA/postponed status; see
  [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md).
- Final `build.ps1 test` and `build.ps1 release -Version 1.5.0-dev` passed.
  Actual Ubuntu host, provider-firewall/public ACME, native Windows client,
  comparative performance and accessibility gates remain open; see
  [`TEST_REPORT.md`](TEST_REPORT.md).

## Prioritized work

| Order | Change | Reason | Principal files | Required evidence / risk |
| ---: | --- | --- | --- | --- |
| 1 | Correct `/proc/stat` guest accounting; request-weight historical error rates; add health-check freshness and CPU hysteresis. | Confirmed metric and status correctness defects; dashboards must not misstate health. | `internal/monitoring/{host,history}.go`, tests; `internal/admin/{server,health_state}.go`, tests. | Deterministic counter/bucket/transition tests; preserve Unknown/stale states; verify existing alert histories. |
| 2 | Share health sampling across bounded SSE subscribers, avoid no-change durable writes and remove the duplicate 30-second full bootstrap poll. | Largest source-derived repeated work and fsync opportunity. | `internal/admin/server.go`, monitoring feed, frontend initialization, tests. | Assert probe/persistence counts at one and max subscribers; reconnect, expiry, initial snapshot and SSE tests. Measure CPU/RSS and request counts under the same fixture before/after. |
| 3 | Make one-time WireGuard config retrieval an authenticated CSRF-protected POST. | State-changing GET can consume the secret through same-site initiation. | `internal/admin/server.go`, `wireguard.html`, React frontend, browser/API tests. | Verify authorization, CSRF rejection, cache headers, complete response, single use and recoverability. Preserve the existing one-time lifecycle. |
| 4 | Harden admin container runtime with read-only rootfs, dropped capabilities, no-new-privileges and bounded `/tmp`. | Reduce compromise impact without adding a service or changing the app boundary. | Production and integration Compose, possibly admin image config. | Startup, health check, temporary writes, persistent writes, package update and rollback tests. Do not alter observer socket permission model. |
| 5 | Apply the six-page layout and shared presentation changes in `DASHBOARD_REDESIGN.md`. | User-facing audit confirms repetition and unclear time scales. | Admin React components/styles, retained templates, browser tests. | All existing flows plus desktop/mobile, keyboard, focus, contrast and empty/error/unavailable states. Review snapshot diff manually. |
| 6 | Remove safe static-analysis noise and unnecessary inline-style CSP exception if code audit confirms no requirement. | Small maintenance/hardening gains. | `internal/release`, `internal/security`, `internal/admin`, tests. | `staticcheck` review; CSP browser tests for React and server-rendered fallback. Keep unrelated style-only capitalization out of scope unless it improves consistency safely. |
| 7 | Repeat dependency and image security triage with a current scanner and database; fix reachable high/critical findings or block release. | First image scan is provisional and Docker Scout was unavailable. | `go.mod`/image base only if evidence supports a change; audit report. | Current Trivy output; per-distinct-CVE reachability and Debian fix-state review; final image scan. No blind base-image update. |

## Validation sequence

1. Focused deterministic Go tests for CPU parsing, weighted aggregation, freshness/hysteresis, shared sample fan-out, unchanged persistence and POST/CSRF download.
2. `go test -cover ./...`, `go vet ./...`, static analysis and both npm audits/build/typecheck/component tests.
3. Existing `pwsh -NoProfile -File .\build.ps1 test` with isolated Docker integration and real browser suite. Repair the baseline screenshot instability before updating an expected image.
4. Browser accessibility/responsiveness journeys and screenshot comparison on desktop/mobile. No new runtime dependency; use existing browser tooling and focused custom assertions.
5. Comparable performance fixture before/after: idle and one-browser container CPU/RSS, 16-SSE health probe/write counts, frontend duplicate requests and large-history chart render/heap.
6. Current image vulnerability scan; resolve or block severe reachable findings.
7. `pwsh -NoProfile -File .\build.ps1 release` to report every mandatory gate. Native Windows/WSL2 and real Ubuntu host checks must be run on the actual required environment; cloud/container equivalence is not sufficient.
8. Final changed-code and diff review; prepare for review. Merge/deploy only after a separate explicit approval.

## Risks and boundaries

- Health sampling is shared state and can introduce synchronization or stale-sample errors; maintain one bounded sampler with explicit age and tests for failures/recovery.
- Weighted error history must preserve current JSON compatibility or use a safe migration-free derivation; no database is introduced.
- POST download must keep browsers' save behavior and one-time transfer semantics while preventing cross-site consumption. Both React and fallback route paths need coverage.
- Compose hardening can expose undocumented filesystem writes; integration tests must enumerate actual writable paths before packaging.
- Layout changes must retain current actions, all six routes, fallback pages and security confirmations.
- The container-health observer remains a high-impact Docker-socket trust boundary under the prior explicit user authorization; no proxy/service redesign is included.
- Current Docker/WSL2 availability and the baseline screenshot difference are verification risks, not grounds to skip required gates.
