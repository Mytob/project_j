# v1.5 Test and Audit Report

**Baseline:** `dev` at `8562b23f0da21fe9f6c17f8367a30171b72b635b`, verified
against GitHub `dev` on 2026-10-18. The first section preserves the pre-change
baseline evidence; candidate results follow it.

## Executed baseline checks

| Command / check | Result | Notes |
| --- | --- | --- |
| `pwsh -NoProfile -File .\build.ps1 test` | **PASS once** | Go unit suite, isolated Docker/container/security/streaming integration, Chromium/Firefox/WebKit and desktop/mobile smoke tests; 4 browser tests. The environment later lost Docker Desktop access. |
| `pwsh -NoProfile -File .\tests\integration\run.ps1` | **FAIL** | Separate repeat: Chromium TOTP security full-page image expected 1440×3241, actual 1440×3287; 4% pixels differ against 1.5% limit. Admin smoke passed in Chromium, Firefox and WebKit. Runner cleanup completed. This is a baseline failure. |
| `go test -cover ./...` | **PASS** | Coverage recorded in `CODEBASE_AUDIT.md`; low entry-point and security package percentages remain. |
| `go vet ./...` | **PASS** | Ran using the pinned Go container image; no diagnostics. |
| `staticcheck@0.8.2 ./...` | **FAIL (findings)** | Deprecated tar aliases, unused test helper, loop simplification and style capitalization warnings; details in code audit. |
| `npm audit --package-lock-only --audit-level=low` (admin frontend and browser test locks) | **PASS** | Zero findings in each lockfile. |
| `govulncheck@latest ./...` | **PASS with module-only advisory** | No reachable vulnerable call or standard-library advisory; `GO-2026-5932` in transitive `x/crypto/openpgp` is unused by this project and has no fixed version. |
| Trivy 0.74.0 scan of local Debian 13.7 security image | **Completed; triage provisional** | 251 findings: 4 UNKNOWN, 84 LOW, 97 MEDIUM, 66 HIGH, 0 CRITICAL. This is finding count, not distinct CVE count. Current Trivy recheck is pending. |
| Docker Scout scan | **BLOCKED** | Installed scanner required Docker account login; no login was attempted. |
| Current Trivy 0.76.0 image rescan | **BLOCKED** | Docker Desktop Linux engine returned named-pipe permission denied in the resumed session. The earlier image export and temp scan artifacts were cleaned. |
| WSL2 host check | **BLOCKED** | `wsl.exe --list --verbose` returned `WSL/E_ACCESSDENIED`; no actual Windows/WSL2 integration claim is made. |
| `pwsh -NoProfile -File .\build.ps1 release` on v1.5 candidate | **NOT RUN AT BASELINE** | Candidate release results are recorded below. |

The baseline integration runner left no test containers (`jellyfin-proxy-m6-57184` was absent after cleanup). No production VPS was contacted.

## Candidate implementation and local gate — 2026-10-18

| Command / check | Result | Evidence |
| --- | --- | --- |
| `pwsh -NoProfile -File .\tests\integration\run.ps1 -UpdateBrowserSnapshots` | **PASS** | Four browser tests passed and the isolated M6/v1.1-v1.4 integration checks completed. Snapshot update was used only after fixing the dynamic security-history screenshot height. |
| `pwsh -NoProfile -File .\build.ps1 test` after final UI fix | **PASS, exit 0** | Go tests, isolated integration, and four browser tests passed, including the Statistics error-rate labeling assertion. |
| `pwsh -NoProfile -File .\build.ps1 release -Version 1.5.0-dev` after final UI fix | **PASS, exit 0** | Local release gate passed: Go tests; Chromium, Firefox and WebKit admin/browser checks; security, Caddy, Fail2ban/nftables, streaming and WireGuard integration; offline image load and package install/update/rollback/preservation/retention/password-recovery checks. |
| `staticcheck@2026.2.2 ./...` in `golang:1.27.2-alpine3.24` | **EXIT 1 (style findings only)** | Safe baseline findings were fixed. It reports 32 `ST1005` error-string capitalization warnings, explicitly out of v1.5 scope; no deprecated tar aliases, unused test helper, or loop simplification findings remain. |
| Trivy 0.76.0 image scan (database pulled 2026-10-18) | **PASS; findings triaged** | All six `jellyfin-proxy/*:1.5.0-dev` images scanned from local archives; final rebuilt admin image rescanned. No CRITICAL findings. Only `security` had HIGH findings: 66 package findings across 13 unique CVEs; Debian Trixie vendor status and application reachability are reviewed in `SECURITY_AUDIT.md`. |
| `git diff --check` | **PASS, exit 0** | No whitespace errors. |

During strict-CSP hardening, the first browser rerun exposed that the
TOTP screenshot fixture itself injected inline CSS. The browser correctly
blocked it; the fixture now serves its test CSS from a same-origin route, and
the final browser and release gates passed with no inline-style CSP errors.

The release gate generated `dist/release-validation-1.5.0-dev.json`, which
records `local_gate: passed` and `release_readiness:
blocked_host_checks_pending`. The local package is
`dist/jellyfin-proxy-1.5.0-dev-linux-amd64.tar.gz`, 125,170,536 bytes, SHA-256
`14a6b4a59cd9da9c40be6f2941f8d2cd95a02cbefa88331d048c743ed01c2994`.
It was built and exercised locally, then deployed to the authorized test VPS.
It has not been published or merged.

### Authorized test VPS deployment — 2026-10-18

- `/root/proxyctl-linux-amd64 update /root/jellyfin-proxy-1.5.0-dev-linux-amd64.tar.gz`
  — **PASS**. The updater verified the current healthy installation, package
  and bundled images, activated `1.5.0-dev`, passed service health and public
  HTTPS readiness, and retained `1.4.2-dev` for rollback. The deployed admin
  image labels the build `8562b23f0da2-dirty`, so this remains a development
  candidate from the modified working tree.
- `docker inspect` across all six application containers — **PASS**; every
  image is tagged `1.5.0-dev`, all report healthy, and restart counts are zero.
  The private `/containers` observer returned healthy snapshots with zero
  restarts for its five observed containers.
- Admin isolation inspection — **PASS**: read-only root filesystem, all
  capabilities dropped, `no-new-privileges`, and a 16 MiB `/tmp` were active.
- Fail2ban status through its configured `/tmp/fail2ban.sock` — **PASS**;
  exactly `jp-admin` and `jp-ssh` are active. The SSH nftables chain contained
  exactly two TCP/22 rules; host sshd journal access from `securityd` passed.
- Normal TLS validation from the VPS — **PASS**: `darkcry.com` 200,
  `admin.darkcry.com` 200, `access.darkcry.com` 403; all had
  `ssl_verify_result=0`.
- WireGuard `latest-handshakes` — **PASS**; one peer was present and its latest
  handshake was 41 seconds old at the check. A request to the Windows peer's
  `http://10.66.66.2:8096/health` from the WireGuard container also passed.
  This verifies the tunnel health endpoint, not a full media playback session.
- Persistent health, TOTP, whitelist, and statistics files remained present;
  the prior release directory remains available. The 2 GiB `/swapfile` was
  active and listed in `/etc/fstab`. After removing the uploaded package and
  updater, the root filesystem had 1.4 GiB available (84% used); Docker images
  were not pruned.
- The user confirmed that native Windows app playback works after the v1.5
  update. Windows firewall configuration and the provider firewall settings
  page were not inspected; public TCP/TLS routes and the UDP WireGuard peer
  were reachable.

### v1.5.1-dev follow-up deployment — 2026-10-19

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.5.1-dev` — **PASS**;
  full local release gate passed. Package:
  `dist/jellyfin-proxy-1.5.1-dev-linux-amd64.tar.gz` (125,332,707 bytes;
  SHA-256 `F8BF1B8F037FC1DD7FE109ED32881AAE952B4AC630396A301ED4A2FB3212CA12`).
- `/root/proxyctl-linux-amd64 update
  /root/jellyfin-proxy-1.5.1-dev-linux-amd64.tar.gz` — **PASS** on the
  authorized test VPS. Persistent data was preserved, services restarted, the
  public HTTPS readiness check passed, and the previous release was retained
  for rollback. Build label: `8562b23f0da2-dirty`.
- Public TLS checks — **PASS**: `darkcry.com` 200,
  `admin.darkcry.com` 200, and default-denied `access.darkcry.com` 403; TLS
  verification succeeded for each.
- All six application containers — **PASS**, healthy with zero restarts.
  Fail2ban `jp-admin` and `jp-ssh` were active. The SSH nftables chain had
  exactly one IPv4 and one IPv6 rule.
- WireGuard interface `server` was present, but the peer's latest-handshake
  timestamp was zero and its transfer counters were zero at the check. The
  tunnel and playback were not confirmed after this update; a live Windows
  client check is still needed.
- The persistent 2 GiB swap remained active. Temporary uploaded package and
  updater files were removed; the VPS root filesystem had 1.4 GiB available
  (85% used).
- The browser regression test covers download/session recovery using a mocked
  response. No authenticated download against the live admin account or
  physical iPhone Safari run was performed.

## Remaining release blockers and unverified work

- Re-scan with current Trivy if image contents change. The candidate's
  0.76.0 scan and HIGH/CRITICAL triage are recorded in `SECURITY_AUDIT.md`.
  Docker Scout was not used because it requires account login.
- Safe baseline static-analysis findings are fixed. The final staticcheck run
  exits 1 only for 32 out-of-scope `ST1005` capitalization warnings.
- No comparable before/after measurements were captured for idle CPU/RSS,
  memory growth, SSE fan-out/probe/write counts under load, browser requests,
  or large-history chart render/heap. Code and deterministic tests support
  reduced duplicate work, but no measured performance claim is made.
- Keyboard navigation, focus, contrast, screen-reader/chart equivalents and
  empty/error-state accessibility have not received a complete objective
  audit.
- Ubuntu host journal, SSH nftables, Fail2ban, public TLS routes, and the
  WireGuard-to-Jellyfin health path passed on the authorized test VPS. The
  user confirmed Windows playback after deployment. Windows/provider firewall
  settings were not directly inspected.
- No stable promotion or publication occurred. The test VPS now runs the
  `1.5.1-dev` dirty development build. The full change still requires final
  code/security review and resolution of the remaining blockers above before
  v1.5 can be called complete.

## Pending gates

- Post-deployment admin follow-ups removed transport-status labels and aligned
  Health status pills across viewport widths; peer handshake/traffic snapshots
  accompany health events. On 2026-10-19,
  `pwsh -NoProfile -File .\tests\integration\run.ps1 -UpdateBrowserSnapshots`
  and `pwsh -NoProfile -File .\build.ps1 test` both passed, including refreshed
  responsive browser snapshots and the isolated M6/v1.1-v1.4 integration
  suite.
- The WireGuard download/session follow-up avoids an immediate admin bootstrap
  request after download, keeps the consumed state through SPA navigation, and
  leaves the loaded admin UI available after a transient status-refresh error.
  Playwright regression coverage passed in the full browser suite. It mocks the
  download response and does not reproduce physical iPhone Safari behavior.
  This follow-up is included in the deployed `1.5.1-dev` package above.
  Windows-local build attempts could not start (`npm` unavailable on PATH; the
  bundled Node.js 24.19.0 attempt lacked the Windows Rolldown binding), while
  the Docker-based frontend build and full release gate passed.
- Current Trivy scan is complete; keep the triaged package-level findings
  under review and re-scan if the image contents change.
- Repeat the full local gates after any further source changes; the final
  candidate's integration and browser gates passed, including the stabilized
  security-page screenshot comparison.
- Windows 11/WSL2-specific checks on the user's actual supported machine.
- Comparable before/after idle, SSE fan-out, browser request, history-render and resource measurements.
- The generated release report records the local gate as passed and its
  pre-deployment host checks as pending. Authorized VPS checks are recorded
  above; direct Windows/provider firewall inspection remains unverified. The
  user confirmed Windows playback after the earlier 1.5.0-dev update; playback
  has not yet been reconfirmed after 1.5.1-dev, whose post-deployment handshake
  check found no active WireGuard client.

Do not interpret unavailable or unexecuted checks as passing. Update this report with exact commands/results as each gate is run.
