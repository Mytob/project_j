# v1.5 Security Audit

**Baseline:** `dev` `8562b23f0da21fe9f6c17f8367a30171b72b635b`, 2026-10-18. This is a source review and controlled local scan record, not a penetration-test certification. Intrusive tests were not run against the VPS.

## Threat boundaries reviewed

Public HTTP enters through Caddy. Access decisions use the socket peer address and default-deny allowlist; forwarded identity headers are not trusted. Caddy admin uses a permissioned Unix socket. The Go admin container does not mount Docker socket. The only documented Docker API path is the separate `containerhealth` observer on an unpublished internal network, which filters application labels and returns a small fixed data model. Host metrics are unprivileged with read-only mounts. `securityd` has host network and `NET_ADMIN` for Fail2ban/nftables only. WireGuard and Caddy share the intended network namespace. Deployment data and secrets are separated from replaceable release files.

## Authentication, API and application controls

Reviewed password hashing and constant-time verification, opaque 32-byte session identifiers, 12-hour expiry and login rotation, secure/HttpOnly/SameSite=Strict cookie settings, global login throttling, TOTP AES-GCM state and replay persistence, password-change reauthentication, session revocation, CSRF on state-changing admin forms, route authorization, input validation, templates/React rendering, command execution, file paths and error responses. External commands use argument arrays rather than shell interpolation. Credential path handling rejects symlinks. No confirmed login bypass, privilege escalation, command injection, stored XSS or path traversal was found in the reviewed paths.

### Findings and residual risk

| Priority | Finding | Evidence and impact | Action |
| --- | --- | --- | --- |
| P2 — resolved in working tree | One-time WireGuard private config was consumed by GET | `GET /wireguard/config` removed the stored private configuration after transfer. SameSite=Strict limits cross-site cookies, but GET could still be initiated from a same-site sibling and cause one-time availability loss. | Changed to authenticated POST protected by CSRF, with no-store headers in both React and fallback forms; browser and package gates passed. |
| P2 — resolved in working tree | Admin runtime hardening was incomplete | Production Compose ran admin non-root but lacked `read_only`, `cap_drop: ALL`, `no-new-privileges:true` and an explicit temporary filesystem. | Added read-only rootfs, all-capability drop, no-new-privileges and a 16 MiB `/tmp`; install/update/rollback package gate passed. |
| P2 residual | Docker daemon API is reachable by the observer process | A read-only socket bind does not make Docker API requests read-only. The observer's own handler exposes only fixed GET operations to admin on a private network, but compromise of the observer process can use the mounted daemon socket with host-level impact. This is the previously authorized restricted Docker API observation path. | Preserve current network/API allowlisting and document the trust boundary. A socket proxy or rootless Docker would change architecture and is not part of this consolidation unless a future security decision authorizes it. Treat observer compromise as high impact in threat model. |
| P3 — resolved in candidate | CSP allowed inline styles | Admin response CSP included `style-src 'self' 'unsafe-inline'`; the fallback statistics page changed its disk bar with a style attribute. | Replaced the fallback bar with a native `<progress>` element, removed the inline-style dependency, and tightened CSP to `style-src 'self'`. Go and Chromium/Firefox/WebKit regression gates passed. |

The risk table separates the observer's **high impact if compromised** from likelihood: it is not public-facing and exposes a fixed application API only to admin, but the socket is full Docker authority from the observer's perspective. The explicit user authorization for restricted Docker API observation is respected; this audit does not silently expand the API or grant the admin container socket access.

## Reverse proxy, network and operations review

- Caddy has no public admin TCP endpoint; allowlist application and trusted socket peer are documented. IPv4, IPv6, CIDR, spoofed forwarded-header and empty-list behavior have isolated integration coverage.
- TLS is Caddy-managed. Production public routing and certificate issuance are environment-dependent; no live-VPS probing was done for this audit.
- WireGuard private material is persisted separately with restrictive permissions; the one-time client configuration flow is the finding above. Peer regeneration clearly revokes prior credentials and is destructive by design.
- Fail2ban attribution, escalating bans, expiry and nftables persistence are handled by `securityd`; isolated tests preserve unrelated firewall state. The v1.4 real-host journal/nftables checks are not repeated here.
- Deployment installer/update logic preserves credentials, allowlist, WireGuard keys, site files and TOTP material; rollback and artifact cleanup are covered by package tests.
- Health endpoints are deliberately minimal; statistics and SSE require admin authentication; collector ports are not published; history and SSE subscriber count are bounded.

## Candidate remediation status

- **Resolved in the working tree:** one-time WireGuard configuration retrieval
  is now an authenticated POST with CSRF validation and no-store response
  headers; the React and fallback forms submit the CSRF token. The local
  release suite passed the one-time download and authorization journeys.
- **Resolved in the working tree:** the admin Compose service now uses a
  read-only root filesystem, drops all Linux capabilities, enables
  `no-new-privileges`, and receives a 16 MiB `/tmp`. Production and isolated
  integration Compose fixtures match, and the local install/update/rollback
  package gate passed.
- **Resolved in the candidate:** removed the CSP inline-style exception after
  replacing the fallback statistics disk bar's style mutation with a native
  progress element. Go tests assert the policy and fallback source; browser
  tests assert the SPA runs with the strict policy. Screenshot-only CSS now
  loads through a same-origin test stylesheet.
- **Resolved in the candidate:** replaced deprecated tar aliases while
  retaining support for zero-flag regular files, removed the unused test
  helper, and simplified ban-history append. Final staticcheck has no such
  findings; 32 remaining `ST1005` error-capitalization warnings are style-only
  and explicitly out of scope.
- The restricted container-health observer remains a high-impact trust
  boundary by explicit prior authorization.

The local release report records only local test and package coverage as
passed. It does not prove actual host journal/nftables enforcement, public TLS,
or Windows client security behavior.

## Dependency and image intelligence

- `govulncheck@latest ./...` exited 0 and reported no vulnerability in reachable source or the Go standard library. It reported module-only `GO-2026-5932` for transitive `golang.org/x/crypto@v0.58.0`; the vulnerable `openpgp` package is not called by this application, and the advisory has no fixed version. See [Go vulnerability database GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932).
- `npm audit --package-lock-only --audit-level=low` reported zero findings for the admin frontend and browser test lockfiles.
- Trivy 0.76.0 scanned all six candidate `jellyfin-proxy/*:1.5.0-dev` images from local archives. After the final CSP rebuild, the final admin image was re-exported and rescanned at 17:53 UTC with a freshly downloaded database: 1 MEDIUM, no HIGH/CRITICAL. The other five images were unchanged from the 17:07 UTC full scan: `caddy` had 1 UNKNOWN and 1 MEDIUM; `containerhealth`, `hostmetrics`, and `wireguard` each had 1 MEDIUM; only `security` had HIGH findings (251 total: 4 UNKNOWN, 84 LOW, 97 MEDIUM, 66 HIGH, 0 CRITICAL). The 66 HIGH package findings map to 13 distinct CVEs, not 66 distinct vulnerabilities.

### Trivy HIGH finding triage — security image

All findings below are in the security container image. Trivy reports Debian
Trixie package versions as affected; Debian's tracker marks these issues
`no-dsa` as minor or postponed, with no Trixie fixed package at scan time.
Review of `securityd`, its configured Fail2ban jails, and Compose capabilities
found no corresponding product call path. The container has `NET_ADMIN` but
not `SYS_ADMIN`; it does not run systemd-homed, parse attacker-supplied HTML or
XML, accept Python TLS server connections, extract untrusted archives, call
libacl pathname APIs, invoke `infocmp`, or invoke the affected util-linux
mount/nsenter paths. These are package-level residual findings, not a claim
that the packages are patched. Track Debian updates and rescan before a stable
release.

| CVE | Package area and vulnerable operation | Debian Trixie status / product reachability review |
| --- | --- | --- |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | ncurses `infocmp` stack overflow | `no-dsa` minor; securityd does not invoke `infocmp`. |
| [CVE-2026-15308](https://security-tracker.debian.org/tracker/CVE-2026-15308) | Python `HTMLParser` CPU denial of service | `no-dsa` minor; active Fail2ban inputs are journal/authentication events, not HTML. |
| [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | systemd-homed local privilege escalation | `no-dsa` minor; no systemd-homed service is configured or launched. |
| [CVE-2026-19445](https://security-tracker.debian.org/tracker/CVE-2026-19445) | Python TLS SNI callback use-after-free | `no-dsa` minor; securityd's TLS client is Go, and Fail2ban is not a Python TLS server. |
| [CVE-2026-19553](https://security-tracker.debian.org/tracker/CVE-2026-19553) | Python `wrap_bio` hostname verification omission | `no-dsa` minor; no Python `wrap_bio` call path was identified. |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | libacl pathname symlink traversal | `no-dsa` pending an upstream/point-release fix; product code does not call libacl pathname APIs. |
| [CVE-2026-7210](https://security-tracker.debian.org/tracker/CVE-2026-7210) | Python Expat hash-flooding with crafted XML | `no-dsa` minor; active Fail2ban inputs do not include attacker-supplied XML. |
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | util-linux mount helper post-hook privilege issue | `no-dsa` minor; no mount path is used and `SYS_ADMIN` is absent. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | `nsenter --join-cgroup` cgroup migration authority | `no-dsa` minor; securityd does not invoke `nsenter`, and `SYS_ADMIN` is absent. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | util-linux `X-mount.subdir` symlink traversal | `no-dsa` minor; no such mount configuration or mount operation is used. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | restricted bind-mount source redirection | `no-dsa` minor; no host fstab is mounted and `SYS_ADMIN` is absent. |
| [CVE-2026-82049](https://security-tracker.debian.org/tracker/CVE-2026-82049) | Python `tarfile` hard-link/symlink extraction | `no-dsa` minor; the security service does not extract untrusted archives. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | Perl Archive::Tar memory exhaustion | `postponed` as minor; the security service does not process Perl tar archives. |

This is a source/configuration reachability review, not a dynamic exploit
verification. The image still contains the affected package versions; any
finding that becomes reachable or receives a Debian Trixie fix must be
reassessed.

Official advisory/status references: [Debian CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742), [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410). Docker's [Engine security documentation](https://docs.docker.com/engine/security/) explains the privilege implications of daemon access.

## Required release follow-up

The candidate's current Trivy scan and distinct HIGH/CRITICAL triage are
complete, including a post-rebuild admin rescan. Repeat them if image contents
change; fix any reachable severe issue or block release. The Docker-socket observer risk remains an explicit
architecture risk under the previously authorized restricted observer
boundary. The GET-to-POST change and admin-container hardening passed the local
regression and package gates.
