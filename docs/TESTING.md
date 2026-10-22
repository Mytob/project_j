# Testing

## v1.6.0-dev.21 Health and Settings fixes — 2026-10-23

- Changes: Health now tolerates null/empty recovery and health-history arrays,
  and the backend serializes fresh recovery history as an empty array. Direct
  `GET /settings` navigation and browser reload now serve the admin SPA.
- Focused command:
  `docker run --rm -v D:/Projects/Project_J2:/src -w /src golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d go test ./internal/admin ./internal/maintenance`
  — PASS; both packages passed.
- Full command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.21 -SupportedUpgradeSources 1.6.0-dev.19` — PASS, exit 0. Go
  tests, frontend typecheck/unit/build, four Playwright browser tests
  (Firefox, WebKit, Chromium, and TOTP flow), M1–M6 integration, isolated
  Fail2ban/nftables and Caddy checks, streaming/WireGuard checks, and offline
  package install/update/rollback/retention/password-recovery checks passed.
  `dist/release-validation-1.6.0-dev.21.json` records
  `local_gate: passed`, `release_readiness: blocked_host_checks_pending`.
- Package: `dist/jellyfin-proxy-1.6.0-dev.21.pkg`, 137,465,696 bytes, SHA-256
  `4e6b65e47bbd5450e0dfc6a61e84c5e5acc418331c02ec56149d9e8697528615`.
  Standalone `dist/proxyctl-linux-amd64`, 14,307,488 bytes, SHA-256
  `aac9d9c6a9928e62aa1ba407c0f29791badde746d8bf215ab4d11f80c6cb1854`.
  This local artifact was built from the working tree at `c29bf990fbef-dirty`;
  it is a test candidate, not a public release.
- Disposable public VPS update: copied the package to `/root`, then ran
  `proxyctl update /root/jellyfin-proxy-1.6.0-dev.21.pkg` and entered the
  independently checked SHA-256 above. The updater verified the package,
  created a pre-update backup, loaded all bundled images, restarted the
  services, passed health and public HTTPS readiness, and retained the active
  and previous releases. `proxyctl --version` reported dev.21;
  `proxyctl doctor` passed and all five app containers were healthy. Docker and
  `jellyfin-proxy-maintenance.service` were active. Public TLS checks returned
  200/200/403 for `darkcry.com`, `admin.darkcry.com`, and `access.darkcry.com`,
  each with `TLS_verify=0`. The public admin root returned 200; unauthenticated
  `/settings` and `/health` redirected to the sign-in page (303), not 404. After
  the operator signed in, `/health` rendered the Health page and `/settings`
  rendered Settings on direct navigation; a full browser reload on `/settings`
  also returned to Settings. The live Health view reported overall Degraded,
  Host metrics Degraded, CPU 100%, and four container components Unknown,
  while the updater and `proxyctl doctor` reported all five app containers
  healthy. Treat Health rendering and Settings reload as passed; the live
  component telemetry discrepancy remains open for investigation. This is the
  user-authorized disposable test VPS; no production release or merge occurred.
- The first dev.20 gate attempts stopped on overly strict test assumptions
  (fresh history always being empty, then a single bootstrap despite the added
  reload). The browser fixture/assertion was corrected; the final dev.21 gate
  passed. Authenticated Health rendering and direct/reloaded Settings both
  passed in the deployed browser. The Health page's Degraded/Unknown live
  telemetry, native Windows acceptance, provider firewall, ACME renewal,
  dashboard update/rollback, and post-update playback remain pending.

## v1.6.0-dev.19 disposable public VPS fresh install and browser acceptance — 2026-10-22

- Target: user-authorized disposable Ubuntu 26.04.1 VPS on `darkcry.com`;
  no production installation was used. The candidate remains dev.19 on
  `fix/v16-maintenance-self-restart`, draft [PR #79](https://github.com/Mytob/project_j/pull/79).
- Artifact transfer: `sha256sum -c jellyfin-proxy-1.6.0-dev.19.pkg.sha256`
  and `sha256sum -c proxyctl-linux-amd64.sha256` — PASS for both files.
  `TERM=dumb /root/proxyctl-linux-amd64 install /root/jellyfin-proxy-1.6.0-dev.19.pkg`
  — PASS; installer completed after public HTTPS readiness. A separate
  `jpadmin` SSH account authenticated and passed `sudo -v` and
  `sudo -n id -u`. Root SSH remained enabled; it was not restricted.
- Host checks: `./proxyctl-linux-amd64 doctor` — PASS for installation files,
  release metadata (1.6.0-dev.19, build `dd026e4a2faa`), Compose
  configuration, all app services, restore/update recovery, Docker Engine,
  Compose and host storage. `docker ps --format '{{.Names}} {{.Status}}'`
  showed admin, securityd, Caddy, WireGuard and hostmetrics all healthy.
  `systemctl is-active docker jellyfin-proxy-maintenance.service` returned
  `active` for both; the scheduled backup timer was enabled and active.
  `docker exec jellyfin-proxy-securityd-1 sh -c 'journalctl --no-pager --output=json -n 1 _COMM=sshd + _COMM=sshd-session | wc -l'`
  returned `1`. Fail2ban status via
  `docker exec jellyfin-proxy-securityd-1 fail2ban-client --socket /tmp/fail2ban.sock status`
  reported both `jp-admin` and `jp-ssh` jails.
- Host firewall: `nft list table inet jp_fail2ban` showed the IPv4 and IPv6
  SSH drop rules. Fail2ban ban/unban checks for reserved test addresses
  `203.0.113.23` and `2001:db8::23` passed; both nftables sets were empty
  after unban. The exact commands included
  `docker exec jellyfin-proxy-securityd-1 fail2ban-client --socket /tmp/fail2ban.sock set jp-ssh banip 203.0.113.23`,
  `nft list table inet jp_fail2ban`, and the matching
  `set jp-ssh unbanip 203.0.113.23`; the same ban/show/unban sequence passed
  for `2001:db8::23`. Host UFW remained inactive. The provider firewall
  settings were not inspected after the VPS rebuild.
- Backup: `./proxyctl-linux-amd64 backup /root/jp16-vps-acceptance.bak`
  and `./proxyctl-linux-amd64 verify-backup /root/jp16-vps-acceptance.bak`
  — PASS; 25 files verified, mode `600 root:root`, SHA-256
  `86e5e246e751dd6f452ad0b1984a6e8d3ebe7eb635b1baaadcb0c971a43dd0be`.
- Reboot: `systemctl reboot` — PASS. After reconnect, the 2 GiB
  `/swapfile` was active and listed in `/etc/fstab`; `proxyctl doctor`
  passed, all five containers returned healthy, the maintenance service and
  Fail2ban jails were active, and the SSH nftables chain was restored.
- External route checks used
  `curl.exe --connect-timeout 8 --max-time 20 -sS -o NUL -w "%{http_code} TLS_verify=%{ssl_verify_result}\n"`
  against `https://darkcry.com/`, `https://admin.darkcry.com/`, and
  `https://access.darkcry.com/` — PASS with 200, 200 and 403 respectively;
  TLS verification returned 0 for all three. A missing base-domain route
  returned 404; unauthenticated `/api/initial` returned 401.
  External TCP probes found 8096, 8080, 8181 and 2019 timed out; 8443 and
  8447 refused connections. Docker published only TCP 80/443 and UDP 51820.
  These observations do not verify the provider firewall configuration or
  certificate renewal.
- Browser smoke check: admin sign-in passed. Overview, Statistics, System,
  Security, Access control, WireGuard, Web Content and About rendered; About
  reported dev.19/build `dd026e4a2faa`. The fresh-install Health page rendered
  blank and the browser console logged
  `TypeError: Cannot read properties of null (reading 'length')`. Settings
  worked through in-app navigation, but reloading `/settings` returned
  `404 page not found`. These are newly observed admin UI defects outside
  this frozen v1.6 change batch; no product code was changed.
- Remaining acceptance: on 2026-10-22 the operator reported that playback
  works. The client and route were not specified, and no supporting handshake,
  Jellyfin health, or direct-public-isolation evidence was recorded. No Windows
  profile was downloaded or imported, and the scoped Windows firewall was not
  inspected. Dashboard update/rollback, authenticated backup download,
  scheduled backup execution, provider-firewall review, ACME renewal, and
  equivalent-workload resource comparison also remain unchecked. The one-time
  WireGuard profile remains available for the operator's Windows test. No
  production deployment, merge, or stable release is claimed.

## v1.6.0-dev.19 clean release gate and Ubuntu package update — 2026-10-22

- Source: clean commit `dd026e4a2faa84285745c7cb63a05bf66174d6f4` on
  `fix/v16-maintenance-self-restart`; draft [PR #79](https://github.com/Mytob/project_j/pull/79)
  targets `dev`.
- Command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.19 -SupportedUpgradeSources 1.6.0-dev.18` — PASS, exit 0. Go
  tests, frontend typecheck/unit/build, four Chromium/Firefox/WebKit admin
  checks, M1–M6 integration/security/streaming, and offline package
  install/update/rollback/retention/password-recovery checks passed. The
  release report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- Focused follow-up: `docker run --rm -v "${PWD}:/src" -w /src
  golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d
  go test ./internal/admin ./internal/webcontent` — PASS, exit 0; both packages
  passed. This ran against the same source candidate; no source changes were
  made after the dev.19 full gate.
- Artifacts: `dist/jellyfin-proxy-1.6.0-dev.19.pkg`, 137,289,488 bytes,
  SHA-256 `a1c656f95fe91f5cd8aab5319d0e7cbbdfb36847077b7d301bf027b578a002df`;
  standalone `proxyctl-linux-amd64`, 14,307,488 bytes, SHA-256
  `e0614bf43e5553b0557bda400941eff1b4c2e1c33f02b85fc3f748e94243abe1`.
  Report: `dist/release-validation-1.6.0-dev.19.json`.
- Exact-package Ubuntu update: Transferred the `.pkg` and sidecar checksum to
  the disposable Ubuntu VM `D:\VM\Ubuntu-v1.6-install-gate\Ubuntu 64-bit.vmx`,
  already running dev.18. `sha256sum -c` passed and `proxyctl update` accepted
  the independently entered expected hash, created its pre-update backup,
  loaded the bundled images, and completed service and HTTPS readiness checks.
  `proxyctl doctor` passed and reported version dev.19/build `dd026e4a2faa`;
  `proxyctl --version` reported dev.19; all five containers were healthy.
- Legacy content migration: Before this fix, the dev.18 upgrade path left the
  default `errors/` directory absent because the old updater performed the
  migration before the new binary was installed. The dev.19 admin startup
  migration created `403.html`, `404.html`, `502.html`, and `503.html` in the
  active persistent site revision. The preexisting `index.html` remained.
- Local Caddy error rendering on the same disposable VM: `curl -ksS -w
  '\nSTATUS:%{http_code}\n' https://jp16.localhost/not-a-real-page` returned
  the default Not found page with HTTP 404; `curl -ksS -w
  '\nSTATUS:%{http_code}\n' https://access.jp16.localhost/` returned the
  default Access denied page with HTTP 403. `-k` was used for the test-only
  local CA. This does not establish public TLS or 502/503 runtime behavior.
- The disposable public VPS and browser results are recorded above.
  Dashboard update/rollback, provider-firewall inspection, ACME renewal,
  internet WireGuard, native Windows client/firewall/playback, and two admin
  UI defects remain unresolved. No production deployment or public release
  was used.

## v1.6.0-dev.17 maintenance self-restart fix — 2026-10-22

- Source: commit `32c6bc15b01bb902bb22265e393f35da6ba08afe` on
  `fix/v16-maintenance-self-restart`; draft [PR #79](https://github.com/Mytob/project_j/pull/79)
  targets `dev`.
- Command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.17 -SupportedUpgradeSources 1.6.0-dev.14` — PASS, exit 0. The
  initial sandboxed attempt could not access Docker Desktop's Linux-engine
  pipe; the retry with Docker access passed. Go, frontend, four real-browser
  checks, integration/security/streaming, offline package install/update/
  rollback, retention and password-recovery gates passed. The generated report
  records `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
- Artifacts: `dist/jellyfin-proxy-1.6.0-dev.17.pkg`, 137,280,003 bytes,
  SHA-256 `194bf444525f4fe9976db73bf83d3e8d44b16a9646c09c09ea8daf6efbd54fb6`;
  standalone `proxyctl-linux-amd64`, 14,303,392 bytes, SHA-256
  `0d465ad823714fb90fe32aa1b8663a2931c2db3d25e7db807dcd0f195ea40b9b`.
  Report: `dist/release-validation-1.6.0-dev.17.json`.
- Exact-package Ubuntu update: The package and independent checksum were
  transferred to the disposable Ubuntu 26.04.1 VM
  `D:\VM\Ubuntu-v1.6-install-gate\Ubuntu 64-bit.vmx`. SHA-256 matched. CLI
  `proxyctl update` moved the guest from dev.14 to dev.17, created the verified
  pre-update backup, loaded the six packaged images, and completed health and
  HTTPS checks. `proxyctl --version` reported dev.17/build `32c6bc15b01b`;
  `sudo proxyctl doctor` passed; all five containers were healthy and the
  maintenance service `ExecStart` pointed to the dev.17 binary.
- Deferred refresh smoke: A five-second `systemd-run --on-active` unit
  restarted the maintenance service while idle. Its invocation ID changed,
  the service remained active, `proxyctl doctor` passed afterward, and all
  five containers remained healthy.
- Dashboard acceptance remains pending: this confirms CLI update and the
  delayed service-refresh mechanism, but does not exercise the dashboard job
  callback. The local admin browser currently requires a fresh sign-in before
  dashboard update/rollback can be tested. No public or production VPS was
  changed; public DNS/ACME/provider-firewall, internet WireGuard and native
  Windows checks remain pending.

## v1.6.0-dev.15 clean-tree gate and Ubuntu update/reboot checks — 2026-10-22

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.15 -SupportedUpgradeSources 1.6.0-dev.14` — PASS, exit 0, from
  clean dev commit `ebd767615ded1abc6fe776a7c229e8c0784c971b`. Go tests,
  M1–M6 integration/security/streaming, frontend validation, four browser
  checks, and offline package installation/update/rollback/recovery passed.
  Six bundled images loaded without registry access. The generated report
  records `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
- Package: `dist/jellyfin-proxy-1.6.0-dev.15.pkg`, 137,277,415 bytes, SHA-256
  `ea14fd5864fcde11d45d23031adbb3abf9be2ee1d3a1fe0f0ceb3991be668064`.
  Standalone `proxyctl-linux-amd64` is 14,303,392 bytes, SHA-256
  `69bf06d16f5da11a475d5ca8cab6101323c6b78d636997a526ffb883868e4b22`.
  Report: `dist/release-validation-1.6.0-dev.15.json`.
- Exact-package update: On the disposable Ubuntu 26.04.1 VMware clone
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` (`192.168.145.136`), the
  transferred package SHA-256 matched. `proxyctl update` from dev.14 to dev.15
  completed, created its pre-update backup, loaded bundled images, passed
  service readiness, and retained active and previous releases. Installed
  `proxyctl --version` reported `1.6.0-dev.15`; `sudo proxyctl doctor` exited 0
  and reported build `ebd767615ded`.
- Host acceptance: All five app containers were healthy. The maintenance
  service and scheduled backup timer were enabled and active. A manual backup
  verified successfully and contained 21 files. The restricted security
  container returned actual host `sshd` journal records and reported the
  `jp-admin` and `jp-ssh` Fail2ban jails. The host `inet jp_fail2ban` SSH chain
  contained one IPv4 and one IPv6 TCP/22 drop rule. Reserved documentation
  addresses `192.0.2.44` and `2001:db8::44` were banned and unbanned; both sets
  were empty and `jp-ssh` reported zero active bans. The WireGuard interface
  listened on UDP/51820 with its configured peer, but no handshake was
  recorded.
- Reboot: After a normal `systemctl reboot`, SSH reconnected to the same clone.
  `proxyctl doctor` passed, all five containers were healthy, maintenance and
  backup units were active, post-boot SSH journal records were visible, and
  Fail2ban plus the one-rule-per-family SSH nftables chain recovered. Both
  address sets remained empty; WireGuard listened on UDP/51820 without a
  recent peer handshake.
- Limits: The broader destructive failure matrix remains the dev.12 evidence;
  it was not repeated against dev.15. No public VPS, provider firewall,
  public ACME, internet WireGuard, or native Windows client/firewall/playback
  test was used. The production VPS and its domains were not changed. No stable
  release or GitHub release is claimed.

## v1.6.0-dev.14 clean-tree gate and Ubuntu update/rollback/update — 2026-10-22

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.14 -SupportedUpgradeSources 1.6.0-dev.13` — PASS, exit 0, from
  clean dev commit `78dfb7987946f011e88dc7cde4660c2d24b12142`. Go tests,
  M1–M6 integration/security/streaming, frontend validation, four browser
  checks, and offline package install/update/rollback/recovery passed. Six
  bundled images loaded without registry access.
- Report: `dist/release-validation-1.6.0-dev.14.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  Public-network and native Windows checks remain pending; this is not a
  stable release.
- Package: `dist/jellyfin-proxy-1.6.0-dev.14.pkg`, 137,278,900 bytes, SHA-256
  `20bacf089d92b4d71b87333004b1f72c83397e5832d0326d8da7c21dbf553601`.
  Standalone `proxyctl-linux-amd64` is 14,303,392 bytes, SHA-256
  `9f79399ff2abfac87e70807582db64d44be4791070f64d98d507d5b814bee719`.
- Exact-package update: On the disposable Ubuntu 26.04.1 VMware clone
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` (`192.168.145.136`), the
  transferred package checksum passed. `proxyctl update
  /tmp/jellyfin-proxy-1.6.0-dev.14.pkg` updated dev.13 to dev.14, created its
  pre-update backup, loaded bundled images, passed service
  readiness, and retained active and previous releases.
- Rollback and restore-to-candidate: `proxyctl rollback` returned the clone
  from dev.14 to dev.13, created a verified pre-rollback backup, passed
  release and HTTPS readiness, and retained current data and the newer
  release. The same dev.14 package then updated dev.13 back to dev.14; its
  update readiness passed and active/previous releases were retained.
- Post-update doctor: `sudo proxyctl doctor` exited 0 and passed installation
  files, release metadata (`1.6.0-dev.14`, build `78dfb7987946`), Compose
  configuration, all five application services, restore/update recovery,
  Docker Engine, Compose, and host storage. `docker ps` reported admin,
  securityd, Caddy, WireGuard and hostmetrics all healthy; the maintenance
  service and scheduled backup timer were active.
- Version-matched Ubuntu host security checks: the security container reported
  exactly `jp-admin` and `jp-ssh` using
  `fail2ban-client --socket /tmp/fail2ban.sock status`. Host `sshd` records
  were returned by its read-only journal mount. The host nftables SSH chain
  contained the IPv4 and IPv6 TCP/22 drop rules. Reserved documentation
  addresses `192.0.2.44` and `2001:db8::44` were banned into their matching
  nftables sets and unbanned; final `jp-ssh` status reported zero active bans.
- WireGuard: `wg show` reported the server interface listening on UDP/51820
  and the configured peer `10.66.66.2/32`. No recent peer handshake was
  reported, so this does not verify internet connectivity or Jellyfin
  playback.
- Fresh install and reboot acceptance: A separate clone of the Ubuntu
  `Fresh Install` snapshot at `D:\VM\Ubuntu-v1.6-install-gate\Ubuntu 64-bit.vmx`
  (`192.168.145.139`) started without the proxy or Docker installed. After an
  apt mirror index hash mismatch, a retried package-index update succeeded;
  Docker Engine and Compose were installed, and the exact dev.14 package and
  sidecar checksums both passed. The installer completed with isolated
  `.localhost` hostnames and a test-only local trust setup for its internal
  HTTPS readiness checks. A separate SSH login as the created host
  administrator succeeded. `proxyctl doctor` passed; all five containers
  were healthy; `jellyfin-proxy-maintenance.service` and
  `jellyfin-proxy-backup.timer` were active. TLS-verified responses were 200
  for the site and admin hostnames and 403 for the access hostname. Backup
  creation and verification passed for 21 files. The restricted container
  observer returned five healthy containers to its authorized UID and 403 to
  root. The two Fail2ban jails, host SSH journal access, and IPv4/IPv6 SSH
  nftables rules passed; reserved test addresses were banned and unbanned.
  After a normal reboot, SSH, doctor, routes, container health, observer
  authorization, services, and security checks passed again. Stopping the
  admin container triggered its bounded recovery job; the container returned
  healthy, the recovery journal recorded the restart, and doctor passed after
  recovery.
- The broader fresh-install/resume, forced interruption, restore recovery,
  low-storage and manual host-maintenance matrix was run against dev.12 on
  disposable clones; it was not repeated against dev.14. The specified
  `D:\VM\Ubuntu` VM was read-only inspected on dev.6; doctor, container health,
  Fail2ban and SSH nftables checks passed, but its WireGuard peer had no recent
  handshake or traffic. It was left unchanged. No production
  VPS/domain was used. Public DNS/provider firewall/public ACME, internet
  WireGuard, and native Windows client/firewall/playback checks remain
  unverified. No stable GitHub release was published.

## v1.6.0-dev.13 clean-tree release gate and Ubuntu update — 2026-10-22

- Command: pwsh -NoProfile -File .\build.ps1 release -Version
  1.6.0-dev.13 -SupportedUpgradeSources 1.6.0-dev.12 — PASS, exit 0, against
  clean dev commit 432b0db7bc7429f0daa2de83ccfd1b219cffb654 after Docker Desktop
  Linux engine access was restored. Go tests, M1–M6 integration/security/
  streaming, frontend typecheck and unit tests, four Chromium/Firefox/WebKit
  browser checks, and offline package install/update/rollback/recovery gates
  passed. Six images loaded without registry access.
- Report: dist/release-validation-1.6.0-dev.13.json records local_gate: passed
  and release_readiness: blocked_host_checks_pending. Public-network and native
  Windows checks remain pending; no stable release is claimed.
- Package: dist/jellyfin-proxy-1.6.0-dev.13.pkg, 137,276,733 bytes, SHA-256
  2c72872dbc1cf5f3e100618fe8295e533b1387e1d859231758d09b4b6c9b4e9e. Its
  independent sidecar checksum passed on the Ubuntu guest.
- Utility: dist/proxyctl-linux-amd64, 14,303,392 bytes, SHA-256
  db53f20494b826156adf545ab36f88cb80e4f1d70b76f52de947792afb496e6f. The
  package build also produced its separate checksum sidecar.
- Exact-package update: On the disposable VMware Ubuntu 26.04.1 clone
  D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx (192.168.145.136), sha256sum -c
  passed for the transferred package. proxyctl update from dev.12 to dev.13
  completed, created its verified pre-update backup, loaded bundled images,
  passed update readiness, and retained the active and previous releases.
- Post-update doctor: sudo proxyctl doctor exited 0. Installation files,
  release metadata (1.6.0-dev.13, build 432b0db7bc74), Compose configuration,
  all five application services, restore/update recovery state, Docker Engine,
  Compose, and host storage all passed.
- Version-matched Ubuntu host checks on that dev.13 clone: `sudo docker ps`
  showed all five services healthy. `sudo docker exec jellyfin-proxy-securityd-1
  fail2ban-client --socket /tmp/fail2ban.sock status` reported the `jp-ssh` and
  `jp-admin` jails. From the same security container,
  `journalctl --no-pager --output=short-iso -n 3 _COMM=sshd` returned actual
  host sshd records and `nft list chain inet jp_fail2ban jp_ssh_input` showed
  the IPv4 and IPv6 TCP/22 drop rules. Reserved test addresses `192.0.2.44`
  and `2001:db8::44` were added to their matching Fail2ban/nftables sets and
  removed; the final `jp-ssh` banned list was empty. `docker exec
  jellyfin-proxy-wireguard-1 wg show` confirmed the server interface listening
  on UDP/51820 and its configured peer; no recent peer handshake was reported.
- Earlier dev.12 testing on disposable clones covered fresh install/resume,
  recovery, rollback, updater interruption, restore interruption, low
  storage, host maintenance, journal, Fail2ban and nftables. The exact dev.13
  package did not repeat that entire destructive failure matrix. The separate
  user-specified `D:\VM\Ubuntu` instance was read-only checked and found on
  dev.5; it was left unchanged because dev.13 only accepts dev.12 as an update
  source. Public DNS, provider firewall, publicly trusted ACME issuance/renewal,
  internet WireGuard, and native Windows client/firewall/playback remain
  unverified. No production VPS/domain was used and no GitHub release was
  published.
## v1.6.0-dev.12 release gate, recovery and update interruption checks — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.12
  -SupportedUpgradeSources 1.6.0-dev.11` — PASS, exit 0. Go tests,
  Chromium/Firefox/WebKit browser checks, M1–M6 integration, streaming,
  security/nftables, frontend, and offline package install/update/rollback/
  retention/recovery checks passed. Six bundled images loaded without registry
  access. `dist/release-validation-1.6.0-dev.12.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  Package SHA-256:
  `f5262ded5603f7a02f21edd6d1e5472a9c081371a3c08d853e7f6ec9dc4f2df3`;
  utility SHA-256:
  `7c3f2b9b369fda01e04ca4bd5f23cc1f8b8f3c9ac2449eb47eecd50e7627786c`.
  The candidate identifies build `8562b23f0da2-dirty` and was built from a
  dirty working tree.
- After the source commit, `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.6.0-dev.13 -SupportedUpgradeSources 1.6.0-dev.12` — BLOCKED before
  tests ran. Docker returned permission denied for the Docker Desktop Linux
  engine named pipe. `docker desktop start` then reported that Docker Desktop
  terminated unexpectedly; `wsl.exe --list --verbose` returned
  `Wsl/E_ACCESSDENIED`, and Go is not installed on the Windows PATH. The
  generated `dist/release-validation-1.6.0-dev.13.json` records
  `local_gate: failed`. The v1.6 implementation had already passed the full
  dev.12 gate above; the clean-tree rerun and a clean dev.13 package could not
  be produced in this resumed environment.
- The recovery run exposed a real bug: the `admin-writer.health` heartbeat was
  counted as a security-event file even though it is not an event JSON record.
  Recovery rejected the otherwise valid backup. `internal/deployment` now
  validates signed JSON records separately, accepts only a safe heartbeat
  marker, and skips that stale marker when restoring events. The regression
  test covers a backup containing both the marker and a signed event. Focused
  `go test ./internal/deployment ./internal/security` and the complete release
  gate passed after the fix.
- Used only the disposable Ubuntu 26.04.1 VMware clones
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` (`192.168.145.136`) and
  `D:\VM\Ubuntu-v1.6-recovery\Ubuntu 64-bit.vmx` (`192.168.145.137`). The
  original `D:\VM\Ubuntu` VM and production VPS/domain were not used. On the
  recovery clone, the dev.12 package, utility and checksum sidecars verified
  with `sha256sum -c`; `proxyctl verify-backup` accepted the dev.11 recovery
  backup (21 files). `sudo proxyctl recover <dev.12 package> <backup>` then
  completed using test-only `.localhost` names and a guest-local Caddy CA.
  A separate SSH session verified the new password-auth administrator and
  `sudo -v` before recovery continued.
- After recovery, all five product containers were Docker-healthy and
  `proxyctl doctor` passed. Recovered public-site files and the SQLite
  statistics database were present. Base/admin/access HTTPS returned
  200/200/403 with certificate verification result 0. The maintenance service
  and scheduled-backup timer were active. The security daemon read actual host
  `ssh.service` journal records; its full health check passed. Reserved IPv4
  and IPv6 test bans appeared in the host's `inet jp_fail2ban` sets, were
  removed, and left both sets empty. After a normal guest reboot, the five
  containers, doctor, maintenance service, backup timer, journal access,
  nftables rules and 200/200/403 HTTPS checks passed again.
- On the separate dev.11 clone, the exact dev.12 package checksum verified.
  `proxyctl update` completed, created a verified 21-file pre-update backup,
  and passed container plus HTTPS readiness. All five containers were
  healthy, `proxyctl doctor` passed, and TLS responses remained 200/200/403.
  `proxyctl rollback` returned to dev.11 and passed its HTTPS readiness checks.
  Forced process termination was injected at each durable update state:
  `prepared`, `stopping`, `replacing`, `starting`, `verifying`, and
  `committing`. Each interrupted transaction was recovered with
  `proxyctl repair`; the committing-stage repair finalized dev.12, while the
  earlier stages returned to dev.11. Forced guest reboots at the same six
  states preserved the corresponding journal, and repair plus `proxyctl
  doctor` passed afterward. A test-only `tests/deployment/vm_fault_injector.py`
  watcher captured the fast committing transition by tracking the updater PID
  before the journal changed. The clone was returned to a healthy dev.12 state.
- A third, linked disposable clone was made from the original VM's `Fresh
  Install` snapshot at `D:\VM\Ubuntu-v1.6-install-interruption\Ubuntu 64-bit.vmx`
  (`192.168.145.138`). The full installer verified the dev.12 package and
  utility checksums, installed Docker Engine and Compose only after approval,
  created and separately verified a password-auth SSH administrator, then
  disabled root SSH login. A forced reboot at the durable install checkpoint
  `ready` preserved the checkpoint and all five healthy containers. After
  locally trusting the clone's Caddy test CA, `sudo proxyctl install --resume`
  completed; `proxyctl doctor` passed and a fresh SSH login plus `sudo -v`
  as the installer-created administrator passed after reboot. Contextual
  `sshd -T -C user=root,...` reported `permitrootlogin no`.
- On that installed clone, a verified 21-file backup was restored with a forced
  process termination at restore journal state `replacing`. The persisted
  `.restore-transaction.json` was observed before repair;
  `proxyctl repair` rolled back to the previous stack, all five services were
  healthy, and `proxyctl doctor` passed.
- A separate 16 KiB tmpfs was filled to exhaustion. `proxyctl backup` then
  failed with `no space left on device`; the application filesystem was not
  filled, the temporary mount was removed, and `proxyctl doctor` still passed.
  The manual `proxyctl host-update` preview listed 35 Ubuntu upgrades (one
  package deferred by phasing); after approval, application and Docker checks
  passed and Ubuntu reported no reboot requirement. `proxyctl doctor` passed;
  both Fail2ban jails were active and the SSH nftables table contained the
  expected IPv4/IPv6 port-22 rules. A new password-auth SSH connection as the
  installer-created administrator and a fresh `sudo -v` succeeded after the
  OpenSSH server package update.
- Public DNS/ACME/provider-firewall checks and native Windows WireGuard,
  firewall, and playback remain unverified. Only disposable VMware clones were
  used; the original VM and production VPS/domain were not changed. At test
  completion no merge or push had occurred; the source was later merged to
  `dev` by [PR #71](https://github.com/Mytob/project_j/pull/71) at `c8e279a`.
  No stable release or production deployment occurred. The generated release
  report remains blocked on public-network and Windows-client checks.
## v1.6.0-dev.11 release gate and clean-guest SSH installation check — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.11
  -SupportedUpgradeSources 1.6.0-dev.10` — PASS. Go tests, M1–M6 integration,
  Chromium/Firefox/WebKit browser checks, security/network checks, and isolated
  package install/update/rollback/retention/recovery all passed. The generated
  `dist/release-validation-1.6.0-dev.11.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  Package SHA-256:
  `f880b5a41ddfe81663d24cd56933aabdf540be6fcc38189462dfb0179e4eef25`;
  utility SHA-256:
  `bbd7d0362321dae3ad2b78dd4f5a3daf6617471de5d127bb7aa8bdf8b5a2037a`.
- Created and used only the disposable clone
  `D:\VM\Ubuntu-v1.6-clean\Ubuntu 64-bit.vmx` (guest `192.168.145.136`),
  based on the `Fresh Install` snapshot of `D:\VM\Ubuntu`. The original VM and
  production VPS were not used. The clone reported Ubuntu 26.04.1 LTS x86-64,
  2 CPUs, 5.2 GiB RAM, and a 9.8 GiB root filesystem.
- Transferred the dev.11 `.pkg`, package checksum, `proxyctl-linux-amd64`, and
  utility checksum to a new `/tmp/jp-v16-dev11` directory. On the guest,
  `sha256sum -c jellyfin-proxy-1.6.0-dev.11.pkg.sha256` and
  `sha256sum -c proxyctl-linux-amd64.sha256` both returned `OK`.
- The first Docker prerequisite attempt stopped before SSH configuration
  because `gb.archive.ubuntu.com` returned mismatched/404 Ubuntu package index
  files while the mirror was syncing. In the clone only, the Ubuntu source was
  temporarily changed to `archive.ubuntu.com`; `sudo apt-get update` then
  completed successfully. The installer installed Docker Engine and Compose
  from Docker's official Ubuntu APT repository. The guest reported Docker
  Engine 29.9.2 and Compose v5.6.1, and the Docker service was active. The
  Ubuntu source URL was restored after the test; Docker remains installed in
  the disposable clone.
- Ran `TERM=dumb sudo ./proxyctl-linux-amd64 install
  ./jellyfin-proxy-1.6.0-dev.11.pkg` interactively with the verified checksum.
  Test-only `jp16.invalid`, `admin.jp16.invalid`, and `access.jp16.invalid`
  entries mapped to the guest in its `/etc/hosts`; public DNS was unchanged.
  The installer reached the separate-SSH-session gate and created a
  password-authenticated test administrator. A new PuTTY SSH session logged in
  as that account; `sudo -v` returned exit status 0. `sshd -T` showed password
  authentication enabled for that account and root remained at its original
  `prohibit-password` policy in the first run.
- A second run selected the optional root-login-disable choice. Afterwards,
  `sshd -T` reported `permitrootlogin no`; a newly opened PuTTY session still
  logged in as the dedicated administrator and its fresh `sudo -v` returned
  exit status 0. The account-specific authentication settings remained active.
- After confirming the verified SSH session, all five product containers
  reached Docker `healthy`. Installation then failed at the expected public
  HTTPS check: Let's Encrypt rejected the reserved `.invalid` names and local
  HTTPS returned a TLS internal error. `proxyctl` reported that installation
  was rolled back. Afterwards, no `jellyfin-proxy` Compose containers or
  `/opt/jellyfin-proxy` remained. The test account and its product-managed SSH
  drop-in were removed, the test `/etc/hosts` entry and temporary Ubuntu mirror
  change were removed, `sshd -t` passed, and effective root policy returned to
  its original `prohibit-password` value. This is evidence for Docker
  prerequisite installation, the
  password-based alternate SSH login/sudo checkpoint, container health and
  application rollback; it is **not** a successful public-domain fresh install.
- Public DNS, provider firewall ingress, publicly trusted ACME issuance and
  renewal, internet WireGuard to Windows, native Windows client/firewall,
  clean-host disaster recovery, public-key SSH login, and the full
  forced-interruption/resume matrix remain unverified. The release report is
  intentionally conservative and remains blocked on host checks.

## v1.6.0-dev.10 release gate, Ubuntu update and image cleanup — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.10
  -SupportedUpgradeSources 1.6.0-dev.7` — PASS, exit 0. Go tests, M1–M6
  integration, Chromium/Firefox/WebKit browser checks, frontend typecheck and
  build, security/streaming/WireGuard coverage, and offline package install,
  update, rollback, retention and recovery passed. All six bundled images
  loaded into the isolated package-validation daemon without registry access.
  `dist/release-validation-1.6.0-dev.10.json` records
  `local_gate: passed`; release readiness remains blocked on host-specific
  checks.
- Candidate package `dist/jellyfin-proxy-1.6.0-dev.10.pkg` is 137,168,582
  bytes with SHA-256
  `b5a6ef17bf61900266867618493c64a1ae995dd85568b4b7e84cd7f82cb69600`;
  `dist/proxyctl-linux-amd64` SHA-256 is
  `4556619332c1d9ad489a49dfdac317a8f5f9f8e9295e09834ddd467df0fa3921`.
  Both were built from working-tree revision `8562b23f0da2-dirty`; they are
  test candidates, not clean or publishable release artifacts.
- The exact package was checksum-verified by `proxyctl update` on the
  disposable Ubuntu Server 26.04.1 clone at
  `D:\VM\Ubuntu-v1.6-fresh\Ubuntu 64-bit.vmx` (`192.168.145.135`). It updated
  from dev.7 to dev.10, retained dev.7 as rollback, created its mandatory
  pre-update backup, and passed service and local HTTPS readiness. The cloned
  VM was the only target changed; the source VM and production VPS were not
  used.
- The cleanup job was invoked through the maintenance Unix socket with peer
  UID 65532. A disposable app-labeled image with no container reference was
  removed; an app-labeled image referenced by a stopped container remained;
  all active and rollback image references remained; and an unrelated image
  and stopped container remained. The completed job reported one image
  removed and one protected/in-use image kept. Temporary test containers,
  images, script, package and updater were removed after the check.
- After cleanup, `proxyctl doctor` passed, all five application containers
  were running/healthy, and the maintenance service and backup timer were
  active. The public DNS/provider-firewall/ACME and native Windows client
  checks remain unverified. Installer SSH administrator setup, clean-host
  recovery, and exhaustive forced interruption/resume coverage also remain
  open. No production deployment, merge, push, or publication occurred.

## v1.6.0-dev.9 full release gate and exact-package Ubuntu update/rollback — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.9
  -SupportedUpgradeSources 1.6.0-dev.7` — PASS, exit 0. Go tests, frontend
  typecheck/build and seven unit tests, four Playwright tests across
  Chromium/Firefox/WebKit at desktop/mobile sizes, M1–M6 integration,
  WireGuard/tunnel recovery, streaming, isolated Fail2ban/nftables IPv4/IPv6,
  and offline package install/update/rollback/retention/recovery passed. The
  package checker loaded all six bundled images into an isolated daemon without
  registry access. The report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- Package `dist/jellyfin-proxy-1.6.0-dev.9.pkg`, 136,987,885 bytes, SHA-256
  `5da7f7fc90c975ca9d6b38f8361c8fc703eb210781325ad7863e695bef8eb1d9`;
  standalone `dist/proxyctl-linux-amd64`, SHA-256
  `fdfbe8834064619b38f8ca081189153f9e51f50c106cbe2b7d2f5e6df6028ab3`.
  Both are built from working-tree source revision `8562b23f0da2-dirty` and
  are test candidates, not clean or publishable release artifacts.
- The disposable Ubuntu Server 26.04.1 clone at
  `D:\VM\Ubuntu-v1.6-fresh\Ubuntu 64-bit.vmx` was on dev.7 after rollback.
  The exact dev.9 package checksum was verified inside the guest before use.
  `proxyctl update` completed to dev.9, retained the previous release, and
  passed its container and local HTTPS readiness checks. `proxyctl doctor`
  passed afterward. `proxyctl rollback` then completed to dev.7 and passed its
  service and local HTTPS checks. A post-rollback `proxyctl doctor` passed;
  all five product containers reported healthy, and the maintenance service
  and backup timer were active. Both the mandatory pre-update backup and
  pre-rollback safety backup passed `proxyctl verify-backup` with 21 files.
- Two earlier dev.8 candidate attempts were stopped safely before activation:
  the first package omitted dev.7 from its supported upgrade sources; a later
  package with that compatibility entry was rejected because another package
  with the same dev.8 version but a different hash was already retained. The
  dev.9 test used a distinct version and preserved the retained-release guard.
- On the rolled-back dev.7 clone, `sudo docker stop jellyfin-proxy-admin-1`
  exercised the persistent maintenance recovery controller. Its state record
  logged `restart_requested` and `restart_sent`; within about 22 seconds the
  admin container was running and healthy again. All five product containers
  were healthy, and `sudo proxyctl doctor` passed. The persisted attempt count
  already included earlier recovery history, so this observation proves
  service restart/readiness, not a fresh retry-limit or backoff sequence.
- This was a private VMware NAT test using local `.localhost` hostnames and the
  existing local test CA; it was not a public DNS/ACME or production VPS test.
  Native Windows WireGuard/firewall/playback, clean-host disaster recovery,
  SSH hardening/alternate-admin verification, clean-host disaster recovery,
  exhaustive fault-injected interruption/resume, safe unused-image cleanup,
  and public provider networking remain unverified. The bounded admin-service
  recovery observation above passed on the disposable VM.
  No production VPS, merge, GitHub publication, or stable release was used.

## v1.6.0-dev.7 full local gate and fresh Ubuntu installation — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0. Go packages,
  M1–M6 integration, admin browser checks, and security/streaming/WireGuard
  regressions passed. The first rerun exposed a test cleanup race in the
  maintenance job fixture; the fixture now waits for persisted terminal job
  state, and the complete command passed on rerun.
- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.7` — PASS,
  exit 0. This repeated the Go, frontend typecheck/build and seven unit tests,
  four Playwright tests across Chromium/Firefox/WebKit and desktop/mobile,
  M1–M6 integration, streaming/range/WebSocket, WireGuard recovery, isolated
  Fail2ban/nftables checks, and offline install/update/rollback/retention and
  credential-recovery checks. The offline package test loaded all six images.
  The report records `local_gate: passed` and
  `release_readiness: blocked_host_checks_pending`.
- Package `dist/jellyfin-proxy-1.6.0-dev.7.pkg`, 136,984,897 bytes, SHA-256
  `a6625aa1277f58bcdfaf3452e32cad4a749c101254d8655c167b396a0caf1319`;
  standalone `proxyctl-linux-amd64` SHA-256
  `68e59b8deb46b705d7ded91071d1786da70561cb0c43eb10a5e96d84be8abf33`.
  The candidate identifies source `8562b23f0da2-dirty`; it is test evidence,
  not a clean or publishable release artifact.
- For a clean-host check, the existing VMware Ubuntu VM was preserved and its
  `Fresh Install` snapshot was cloned to
  `D:\VM\Ubuntu-v1.6-fresh\Ubuntu 64-bit.vmx`. The clone booted Ubuntu Server
  26.04.1 LTS at `192.168.145.135`, with no existing Jellyfin Proxy install,
  Docker, or Compose. The package, package checksum, utility, and utility
  checksum were transferred; guest-side checksum verification reported `OK`.
  The install approved and completed the official Docker Engine/Compose APT
  prerequisite path, then installed `1.6.0-dev.7` using local-only
  `.localhost` domains and a temporary local Caddy CA. An initial attempt
  safely rolled back because the test CA was not trusted by the installer
  process; after adding that local test CA to the guest trust store, the
  install completed and the local certificate checks verified successfully.
- On the fresh clone, `proxyctl doctor` passed. All five application
  containers (admin, Caddy, hostmetrics, securityd, and WireGuard) reported
  healthy. The maintenance service and automatic-backup timer were active; a
  backup completed and `proxyctl verify-backup` verified its 21 files. The
  admin UID received HTTP 200 from the restricted container observer and root
  received HTTP 403. Host SSH journal records were visible to securityd; both
  Fail2ban jails were active. Reserved documentation IPv4 and IPv6 addresses
  were banned and unbanned, with the corresponding host nftables sets changing
  and returning empty.
- After a normal guest reboot, all five containers remained healthy, the
  maintenance service and backup timer were active, both Fail2ban jails and
  the host nftables SSH chain were present, `proxyctl doctor` passed, and the
  restricted observer still denied root and allowed UID 65532. Guest-local
  TLS checks returned 200 for the base and admin domains and the expected 403
  for the default-deny access domain, each with certificate verification
  result 0.
- This check used a private VMware NAT network and local `.localhost`
  certificates. Public DNS/provider firewall/ACME issuance and renewal,
  internet WireGuard connectivity to a Windows Jellyfin host, native Windows
  import/firewall/playback, clean-host disaster recovery, and forced
  interruption at each update/restore stage remain unverified. No production
  VPS, public domain, GitHub merge, or publication was used.

## v1.6.0-dev.6 release gate and disposable Ubuntu maintenance-job check — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev.6
  -SupportedUpgradeSources 1.6.0-dev.5` — PASS, exit 0. The report records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  Go tests, frontend typecheck/build/seven unit tests, Chromium/Firefox/WebKit
  browser tests, security/streaming/WireGuard integration and the isolated
  offline package install/update/rollback gate passed. The package gate loaded
  all six images offline and passed install, update, rollback, retention, TOTP
  recovery and password reset. The expected port-80 conflict failed safely and
  preserved its unrelated container.
- Focused `go test ./internal/deployment ./cmd/proxyctl
  ./internal/maintenance ./cmd/maintenance` — PASS after adding restart-on-unit-
  change coverage for the active maintenance service.
- Package `dist/jellyfin-proxy-1.6.0-dev.6.pkg`, 136,575,819 bytes, SHA-256
  `85d6e0d6551089227e91edfd859650f274f421211344043edb0956626fb2b273`;
  standalone `proxyctl` SHA-256
  `c3933e88e6a1a93aab37ed3069d2311bf66b717910e3eb688472d3fdc0905108`.
- The package and checksum were copied to the disposable VMware Ubuntu guest;
  `sha256sum -c` reported `OK`. `proxyctl doctor` passed before and after the
  `1.6.0-dev.5` → `1.6.0-dev.6` update. The updater created and retained its
  verified pre-update backup. The active/previous releases and persistent data
  remained in place.
- The update exposed that `systemctl enable --now` does not restart an already
  active maintenance process after its unit changes. The updater now invokes
  the just-installed `proxyctl` to reconcile host unit templates; unit changes
  restart an active maintenance service. On the VM the service ran the dev.6
  executable, systemd created `/var/lib/jellyfin-proxy-maintenance` and its
  `jobs` directory as root mode `0700`, and the unit had
  `StateDirectory=jellyfin-proxy-maintenance`, `StateDirectoryMode=0700` and
  `ReadWritePaths=/var/backups/jellyfin-proxy`.
- Through the maintenance Unix socket, root received HTTP 403 and UID 65532
  received HTTP 200. UID 65532 submitted a fixed backup job (HTTP 202); it
  completed at step 2/2, remained completed after restarting the maintenance
  service, and appeared in the backup list. Its record was root-owned mode
  `0600`. `proxyctl verify-backup` passed for the generated 22-file archive.
- All five application containers were `running/healthy` with zero restarts.
  Guest-local HTTPS checks returned static 200, admin 200, and expected access
  403, all with `tls=0`. The restricted observer returned five healthy
  container snapshots to UID 65532.
- This remains a disposable private-NAT guest check: public DNS/provider
  firewall/ACME and native Windows WireGuard/firewall/playback checks remain
  unverified. Other required v1.6 dashboard/recovery scope and forced
  interruption coverage remain open. No stable release, merge, publication or
  production VPS deployment is claimed.

## v1.6 local release gate and Ubuntu VM checks — 2026-10-22

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev` — PASS,
  exit 0 after the Docker API compatibility and restore ownership fixes. Go tests, frontend
  typecheck/build/seven unit tests, Chromium/Firefox/WebKit browser tests,
  security/streaming/WireGuard integration, and the isolated offline
  install/update/rollback suite passed.
  The package gate loaded all six images without registry access and exercised
  install, update, rollback, retention, TOTP recovery, and password reset.
- The first full integration rerun after the observer change failed when the
  trusted test client was still receiving HTTP 403 after the whitelist update.
  A clean repeat passed the whitelist propagation check and the complete M1–M6
  and browser suite. The subsequent full release gate passed. Earlier on
  2026-10-22, fixed-port and stale-fixture failures were also corrected in the
  local harness; the runner now selects distinct free ports and clears the
  disposable credential fixture before use.
- Report: `dist/release-validation-1.6.0-dev.json`; `local_gate: passed`,
  `release_readiness: blocked_host_checks_pending`. The intentional host-port
  80 conflict case in the isolated installer gate failed safely and preserved
  the unrelated conflict container.
- Release-gate package SHA-256:
  `d6c20e0ebf31b18072fb2da902f26b6e938aa6eb1e1154a9757633715822e511`.
  The standalone `proxyctl` SHA-256 is
  `23156243bf3c1923a30bbd6199c01ea9e5f5027f5de9aa99e092edcfa597e9b4`.
- The release package and its checksum sidecar were copied to `/tmp` on the
  disposable VMware guest at `192.168.145.131`; guest-side `sha256sum -c`
  reported `OK`. A fresh v1.6 candidate was installed on the VM using local
  `.localhost` names and a temporary local Caddy CA; Docker and Compose were
  already installed. No public ACME or production domain was used.
- Docker Engine 29.1.3 advertises API 1.52 and requires minimum API 1.44. The
  initial host observation returned 503 because the observer hard-coded API
  1.41. The observer now negotiates the daemon/client intersection and selects
  the lowest compatible API. Focused `internal/containerhealth` and
  `internal/maintenance` tests pass. On the VM, the rebuilt maintenance binary
  from the verified package returned five managed container snapshots, all
  `running/healthy` with zero restarts. The admin UID received HTTP 200 and
  root received HTTP 403. Both checks still passed after reboot.
- After reboot, the maintenance systemd service and backup timer remained
  enabled and active; all five application containers were healthy; the local
  static and admin HTTPS routes returned 200 and the default-deny access route
  returned 403; both Fail2ban jails were active; and host SSH journal records
  were present. Reserved IPv4 and IPv6 test bans reached the product nftables
  sets and were removed; the pre-existing `inet jp_fail2ban` table was kept.
- A test-only `1.6.0-dev.1` package was used to test the updater from
  `1.6.0-dev`. It first rejected an unsupported source without mutation. After
  rebuilding with the source explicitly allowed, one attempt safely rolled
  back because the local CA was not trusted by that process; a retry with the
  temporary test CA completed. The pre-update `.bak` passed `proxyctl
  verify-backup`, `proxyctl doctor` passed, and services/routes remained
  healthy after a normal guest reboot. `dev.1` is not a release artifact.
- Restore testing exposed an ownership defect: archive extraction preserved
  modes but not host UID/GID, leaving restored admin data inaccessible. After
  recursively applying the required ownership/mode policy and requiring all
  five managed containers for readiness, `proxyctl restore` completed on the
  VM from a test-only `1.6.0-dev.1` backup. It created a safety backup before
  changes; all five containers reached `running/healthy`; the local HTTPS
  check passed; the transaction journal was removed; whitelist and SQLite
  history files were restored as `65532:65532` mode `0600`; and the
  security-event spool returned with its restricted ownership and modes. The
  restore-created 22-file safety backup passed `verify-backup`. Restore
  progress reported seven milestones instead of remaining at 0% during
  readiness checks.
- This confirms private-NAT Ubuntu installation/update, journald,
  Fail2ban/nftables, container observation, normal reboot recovery and the
  restore success path, but not a clean-OS prerequisite install, forced
  interruption at every update/restore stage, fresh-host disaster recovery,
  public DNS/provider firewall/ACME, or native Windows WireGuard/firewall
  checks. No production VPS was touched.
- v1.6 remains in progress; see the implementation gaps in
  [`v1.6/CODEBASE_AUDIT.md`](v1.6/CODEBASE_AUDIT.md). No stable release,
  publication, merge, or production deployment is claimed.

## v1.6.0-dev local release gate and disposable Ubuntu VM checks — 2026-10-21

- **Local release command:** `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.6.0-dev` — PASS, exit 0. The generated report records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
- **Automated coverage:** all Go packages; frontend typecheck, build and seven
  unit tests; Chromium, Firefox and WebKit admin/browser scenarios; existing
  M1–M6 proxy, streaming, WireGuard, security, Fail2ban and nftables regressions;
  and the isolated offline package install/update/rollback gate. The package
  gate loaded six images without registry access and exercised fresh install,
  namespace ingress firewalls, SQLite history and persistent-data retention,
  online update, forced post-update failure/rollback, TOTP backup/recovery and
  password reset. Its deliberate port-80 conflict case failed installation as
  expected and preserved the unrelated conflict container.
- **Disposable host:** VMware guest at `D:\VM\Ubuntu`, Ubuntu Server
  26.04.1 LTS x86-64, kernel `7.0.0-38-generic`, 2 CPUs, 5.2 GiB RAM, 9.8 GiB
  root filesystem. Docker Engine 29.1.3 and Compose 2.40.3 were installed for
  testing. `systemd-journald` and SSH were active; `journalctl -u ssh` returned
  host records; `sshd -T` reported `permitrootlogin prohibit-password`,
  `passwordauthentication yes`, and `pubkeyauthentication yes`. nftables
  1.1.6 was present. `modprobe wireguard`, creation of a temporary WireGuard
  link and its deletion all succeeded. The guest had no swap and about 5.9 GiB
  free at the recorded post-prerequisite check.
- **Package CLI:** the packaged `.pkg`, package SHA-256 sidecar, standalone
  `proxyctl` binary and its checksum were copied to the guest. Both
  `sha256sum -c` checks passed. `proxyctl --help` ran. `proxyctl doctor`
  correctly reported that no product installation exists (and therefore its
  installation path/disk query cannot be inspected); Docker and Compose probes
  passed. `proxyctl install <package>` independently validated the supplied
  checksum and package, presented every installer field and the final review,
  then was cancelled before deployment. Follow-up checks confirmed
  `/opt/jellyfin-proxy` remained absent, SSH remained active, no product
  nftables table existed, and no Jellyfin Proxy containers were created.
- **VM limitation:** no VMware snapshot could be created in the available
  session. The guest is private NAT; it cannot receive the public ACME
  challenge or verify provider firewall ingress. We did not install the
  application, add host firewall rules, configure Fail2ban, touch public DNS,
  or deploy to the production VPS. Consequently host journal consumption from
  the deployed security container, actual host SSH bans, host reboot recovery,
  public certificate issuance and renewal, and native Windows client/firewall
  checks remain blocked or unexecuted. `proxyctl doctor` is a read-only
  diagnostic and its expected missing-install failures are not a release-gate
  failure.
- **Artifacts:** `dist/jellyfin-proxy-1.6.0-dev.pkg`,
  `dist/jellyfin-proxy-1.6.0-dev.pkg.sha256`,
  `dist/proxyctl-linux-amd64`, `dist/proxyctl-linux-amd64.sha256`, and
  `dist/release-validation-1.6.0-dev.json`. These are development artifacts;
  no stable release or publication is claimed.
- **Product completion:** the local release gate passing does not complete
  v1.6. The audit lists remaining required work, including the durable update
  interruption/reboot test matrix, admin System APIs and resumable package uploads, Web Content
  archive/custom error-page management, About component inventory, bounded
  persistent service recovery, and fresh-host recovery/failure-injection
  coverage. No implementation is considered complete based on file presence.

## v1.6 update crash-recovery follow-up — 2026-10-21

- The update transaction now has a durable journal and fsynced private rollback
  snapshot. `proxyctl repair` resumes recovery after interruption, and backup
  cleanup protects the transaction's mandatory pre-update archive.
- `docker run --rm -v D:/Projects/Project_J2:/src -w /src
  golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d
  go test ./internal/deployment ./cmd/proxyctl` — PASS after the change.
  Tests cover interrupted activation recovery, the prepared stage,
  retaining the journal when health recovery fails and succeeding on retry, a
  verified commit, malformed journal refusal, and protecting the active backup.
- `pwsh -NoProfile -File .\build.ps1 release -Version 1.6.0-dev` — PASS,
  exit 0 after the update-recovery changes. The JSON report records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
  Go tests, frontend typecheck/build/unit tests, Chromium/Firefox/WebKit
  browser tests, security/streaming/WireGuard integrations, and isolated
  offline package install/update/rollback all passed. Six images loaded without
  registry access; install, update, rollback, persistent data, and password
  reset checks passed. The expected port-80 conflict failure preserved the
  unrelated container.
- Package SHA-256:
  `c6fab4a81399b4df9717ce7a940fc339014d61d51e7705f0de783aed365b9a04`.
  Standalone `proxyctl` SHA-256:
  `17352ec9dc257afd7870fb3b5a21a506b76eb1241668d088ac5c98bf39fc005a`.
  Machine report: `dist/release-validation-1.6.0-dev.json`.
- Forced VM power-off at every update stage remains outstanding. Do not treat
  the unit-level recovery simulations as VM reboot acceptance.

## v1.5 audit baseline — 2026-10-18

The audit baseline and limitations are recorded in
[`v1.5/TEST_REPORT.md`](v1.5/TEST_REPORT.md). Observed commands/results:

- `pwsh -NoProfile -File .\build.ps1 test` — passed once, including Go,
  isolated Docker integration and four browser tests.
- `pwsh -NoProfile -File .\tests\integration\run.ps1` — separate repeat
  failed the Chromium TOTP security full-page screenshot comparison (expected
  1440×3241, rendered 1440×3287, 4% pixels differed against 1.5%). Other admin
  smoke browser checks passed; cleanup completed.
- `go test -cover ./...` and `go vet ./...` — passed.
- `staticcheck@0.8.2 ./...` — reported deprecated tar aliases, one unused
  test helper, a loop simplification and style-only error-string warnings.
- `npm audit --package-lock-only --audit-level=low` — zero findings for the
  admin and browser-test lockfiles.
- `govulncheck@latest ./...` — no reachable vulnerable call; reported the
  unused transitive OpenPGP package advisory `GO-2026-5932`.
- Trivy 0.74.0 security-image scan — 251 findings (4 UNKNOWN, 84 LOW,
  97 MEDIUM, 66 HIGH, 0 CRITICAL); current Trivy rescan is blocked by the
  unavailable Docker Desktop Linux engine. Docker Scout required login and was
  not used.
- `wsl.exe --list --verbose` — blocked with `WSL/E_ACCESSDENIED`.

These are historical baseline checks before the v1.5 implementation. The
candidate checks run on 2026-10-18 are recorded below; unexecuted checks remain
pending rather than passed.

## v1.5 candidate checks — 2026-10-18

- `pwsh -NoProfile -File .\tests\integration\run.ps1 -UpdateBrowserSnapshots`
  — PASS, 4 browser tests and the full isolated M6/v1.1-v1.4 integration suite.
  This refreshed expected images after the dynamic security-history viewport
  was made fixed-height in the screenshot setup.
- `pwsh -NoProfile -File .\build.ps1 test` — PASS, exit 0, including Go tests,
  full isolated integration and four desktop/mobile browser tests.
- `pwsh -NoProfile -File .\build.ps1 release -Version 1.5.0-dev` — PASS,
  exit 0. The normal screenshot comparison passed; isolated streaming,
  WireGuard recovery, security/firewall checks, offline image loading, package
  install/update/rollback, data preservation, retention and password recovery
  passed. Seven images were loaded into an isolated daemon without registry
  access. `dist/release-validation-1.5.0-dev.json` records
  `local_gate: passed` and, at the time it was generated,
  `release_readiness: blocked_host_checks_pending`.
- `staticcheck@2026.2.2 ./...` in `golang:1.27.2-alpine3.24` — EXIT 1 on 32
  out-of-scope `ST1005` capitalization warnings only. The safe findings from
  the baseline (deprecated tar aliases, unused helper, loop simplification)
  are fixed.
- `docker pull aquasec/trivy:0.76.0`, local `docker save` archives and the
  Trivy image scan — PASS; all six product images scanned. After the final
  admin UI rebuild, its image was rescanned; only the security image has HIGH
  findings. Detailed counts and triage are in `v1.5/SECURITY_AUDIT.md`.
- `git diff --check` — PASS, exit 0.

## Admin session recovery follow-up — 2026-10-19

- `pwsh -NoProfile -File .\tests\integration\run.ps1 -UpdateBrowserSnapshots`
  — PASS, four browser tests and the complete isolated M6/v1.1-v1.4 integration
  suite. Refreshed snapshots to match the intentionally removed “Live via SSE”
  label.
- `pwsh -NoProfile -File .\build.ps1 test` — PASS; all Go packages, the
  isolated integration suite, and all four browser tests passed.
- Browser regression coverage verifies that a successful WireGuard download
  switches the action to regenerate without another bootstrap request and
  keeps that state after SPA navigation. A temporary admin-status refresh
  failure leaves the page usable and its retry control succeeds. Download
  responses are mocked in this browser test; Playwright WebKit is not a real
  iPhone Safari run.
- No physical iPhone Safari reproduction was performed. The subsequent VPS
  deployment and checks are recorded below.

The final package is `dist/jellyfin-proxy-1.5.0-dev-linux-amd64.tar.gz`
(125,170,536 bytes; SHA-256
`14a6b4a59cd9da9c40be6f2941f8d2cd95a02cbefa88331d048c743ed01c2994`).
It remains a local artifact, not a published release, and was deployed to the
authorized test VPS using the standalone updater on 2026-10-18. The updater
completed its image, service-health and public HTTPS readiness checks and kept
`1.4.2-dev` for rollback. Post-deployment checks found all six containers
healthy with zero restarts, the private container observer healthy, valid TLS
on `darkcry.com` and `admin.darkcry.com` (200) and the expected 403 on
`access.darkcry.com`, both Fail2ban jails active, SSH journal access working,
and exactly two TCP/22 nftables rules. A recent WireGuard handshake and the
tunneled Jellyfin `/health` endpoint also passed. Persistent health, TOTP,
whitelist and statistics files remained present; 2 GiB persistent swap was
active. The deployed admin build reports `1.5.0-dev`, build
`8562b23f0da2-dirty`.

The user confirmed on 2026-10-18 that Windows Jellyfin playback works after
this update. Direct Windows firewall confirmation and inspection of the
provider firewall settings remain pending, along with objective
keyboard/focus/contrast/screen-reader checks, comparable before/after
idle/SSE/chart-render performance measurements, and final changed-code review.
The VPS deployment was to the authorized test VPS; no stable promotion or
publication occurred. The Jellyfin health endpoint check does not prove a full
media playback session.

After that deployment, a working-tree follow-up removed the SSE status badges
and "Rarely changed" label, aligned Health component state pills at all
viewport widths, and added current WireGuard peer snapshots to health events
so the tunnel card refreshes without reloading. These changes were included in
the later `1.5.1-dev` package below.

A further local change removes the admin bootstrap refresh after a successful
one-time WireGuard configuration response, preserves the consumed state while
the SPA remains open, and keeps loaded admin pages available after transient
refresh errors. Windows-local npm/Vite build attempts were unavailable due to
the missing Windows Rolldown binding; the Docker-based frontend build and the
full browser, integration, and release gates passed. The resulting
`1.5.1-dev` package was deployed and checked as follows.

## v1.5.1-dev VPS update and post-deployment checks — 2026-10-19

- `pwsh -NoProfile -File .\build.ps1 release -Version 1.5.1-dev` — PASS. The
  complete local release gate passed, including Go, browser, isolated service
  integration, offline image loading, package update/rollback and preservation
  checks. Package:
  `dist/jellyfin-proxy-1.5.1-dev-linux-amd64.tar.gz` (125,332,707 bytes;
  SHA-256 `F8BF1B8F037FC1DD7FE109ED32881AAE952B4AC630396A301ED4A2FB3212CA12`).
- `/root/proxyctl-linux-amd64 update
  /root/jellyfin-proxy-1.5.1-dev-linux-amd64.tar.gz` on the authorized test VPS
  — PASS. The updater validated the current install and package, preserved
  persistent data, activated `1.5.1-dev`, restarted services and passed its
  public HTTPS readiness check. The previous release remains available for
  rollback. The deployed admin image labels the build
  `8562b23f0da2-dirty`.
- Public HTTPS checks with normal TLS verification — PASS:
  `darkcry.com` 200, `admin.darkcry.com` 200, `access.darkcry.com` 403;
  certificate verification succeeded for all three.
- `docker ps --format '{{.Names}} {{.Status}}'` — PASS; all six application
  containers reported healthy. The post-update inspection found zero restarts.
- `fail2ban-client --socket /tmp/fail2ban.sock status` — PASS; both `jp-admin`
  and `jp-ssh` jails were active. The live SSH nftables chain had exactly one
  IPv4 and one IPv6 source-address rule.
- `wg show server latest-handshakes` and `wg show server transfer` completed,
  but the configured peer reported handshake timestamp 0 and zero transferred
  bytes at that observation. No active tunnel or post-update playback was
  proven. The WireGuard interface is named `server`.
- The 2 GiB persistent swap remained active. After deployment and removal of
  the two temporary upload files, `/` had 1.4 GiB available (85% used).
- The browser regression tests exercise a mocked one-time download response;
  no authenticated download against the live admin account or physical iPhone
  Safari run was performed. A user-side client check is still needed to verify
  session recovery and streaming after this update.

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

### v1.3.5-dev single WireGuard lifecycle action — 2026-10-17

- **Behavior:** The Windows peer panel now has one action only. It says
  “Download configuration” while the one-time file is available and changes
  to “Regenerate and revoke current peer” after the complete response is
  received. Removed the state badge, helper paragraphs, transient notices,
  refresh link, rotation confirmation, and `rotated` query marker.
- **Browser coverage:** Updated the Chromium flow for both button states,
  failed-download retry behavior, and the absence of peer status messages.
  Refreshed only the WireGuard desktop and mobile visual baselines. The first
  runs caught an obsolete state-badge assertion and stale mobile baseline;
  both were corrected before the passing run.
- **Validation:** On clean merged `dev` commit `f4803a4474b1`,
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.5-dev` — PASS,
  exit 0. Go tests, frontend typecheck/six unit tests/build,
  Chromium/Firefox/WebKit browser coverage, monitoring/streaming integration,
  and offline package install/update/rollback/retention/password-reset checks
  passed. `dist/release-validation-1.3.5-dev.json` records
  `local_gate: passed` and `release_readiness: blocked_host_checks_pending`.
- **Package:** `dist/jellyfin-proxy-1.3.5-dev-linux-amd64.tar.gz`, SHA-256
  `17ce10b37348c4a92e4be68100248f1e198a28b885e622774cbe2971c28ff70e`.
- **VPS update:** The updater completed successfully on the authorized Ubuntu
  test VPS and reports version `1.3.5-dev`. All five services report healthy;
  the active and previous releases are retained. The WireGuard config endpoint
  was not invoked during the update.
- **Public routes:** `darkcry.com` returned 200, `admin.darkcry.com` returned
  200, and `access.darkcry.com` returned 403. All three had TLS verification
  result 0.
- **Limits:** Native Windows client import, firewall, and playback checks were
  not performed for this build.

### v1.3.6-dev friendly IP names and simplified WireGuard diagnostics — 2026-10-17

- **Behavior:** Administrators can add an optional friendly name to each
  allowlisted IP/CIDR and edit or clear it later. Names are persisted as
  display metadata and never enter the Caddy access policy. Address-only v1
  whitelist files migrate on their next write. The redundant Jellyfin
  health-response tile was removed from the WireGuard tunnel status panel;
  Overview and Health still report component health.
- **Browser coverage:** The Chromium flow adds, renames, and removes a named
  address, and checks that tunnel diagnostics contain only the peer and byte
  counters. Updated the Access Control and WireGuard desktop and mobile visual
  baselines. The first integrated browser run exposed a fixture issue: removing
  its temporary IP left the mock streaming route denied. The fixture now seeds
  the browser test IP into the admin allowlist; the rerun passed all four
  browser tests, including Firefox and WebKit smoke checks and Caddy streaming,
  range, and WebSocket coverage.
- **Release gate:** Clean-tree
  `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.6-dev` on commit
  `a8a7937cd68b` — PASS, exit 0. Go tests, frontend typecheck, six frontend
  tests, production build, four browser tests, monitoring and streaming
  integration, and isolated offline install/update/rollback, retention, and
  password-recovery checks passed. The report records
  `local_gate: passed`; host-specific v1.3 checks remain blocked.
- **Package:** `dist/jellyfin-proxy-1.3.6-dev-linux-amd64.tar.gz`, SHA-256
  `e6175e8b4b46f76fb76835dffaacc6b843bfc6900273eac227be661328caa3b3`.
- **VPS update — 2026-10-17:** The package SHA-256 matched after transfer to
  the authorized Ubuntu 26.04.1 x86_64 test VPS. `proxyctl update` completed
  successfully with version `1.3.6-dev`; the admin image reports build
  `a8a7937cd68b`. The active and previous releases are retained. All five
  application containers report healthy, and the Windows WireGuard peer
  established a fresh handshake after the service restart.
- **VPS resource incident:** Docker and containerd API calls stalled under
  severe memory pressure on the 833 MiB, no-swap host during the first image
  import/verification attempt. `systemctl restart docker` restored the Docker
  API; `docker compose ... up -d` restored the existing `1.3.5-dev` stack. A
  temporary 1 GiB `/swapfile` (`fallocate`, `mkswap`, and `swapon`) let image
  import and verification finish. `swapoff /swapfile` and `rm -f /swapfile`
  removed it after the successful update; no swap configuration was added to
  `/etc/fstab`.
- **Public routes:** Normal TLS verification returned `darkcry.com` 200,
  `admin.darkcry.com` 200, and `access.darkcry.com` 403; all three reported
  `ssl_verify_result=0`.
- **Limits:** The WireGuard handshake was verified, but native Windows client
  playback was not repeated after this deployment. Windows import, firewall,
  and playback checks remain pending for this build.

### v1.3.6-dev post-update Windows playback confirmation — 2026-10-17

- The operator confirmed that Jellyfin playback works from the native Windows
  client through the test VPS after its 1.3.6-dev update.
- The Windows WireGuard profile and scoped inbound firewall setup were already
  confirmed during the earlier host gate. The v1.3.6 update did not change the
  Windows configuration; the VPS observed a fresh peer handshake after restart.
- Together with the recorded VPS health and valid public TLS routes, this closes
  the v1.3 host-specific checks. Version-matched evidence for the stable
  1.3.6 release is recorded in
  [release-host-checks-v1.3.6.json](release-host-checks-v1.3.6.json). The
  stable release gate passed; see the results immediately below.
### v1.3.6 stable release gate — 2026-10-17

- Command: `pwsh -NoProfile -File .\build.ps1 release -Version 1.3.6 -HostCheckEvidence dist/release-host-checks-v1.3.6.json` — PASS. The first attempt could not access Docker Desktop from the sandbox; the retry with Docker engine access completed the gate.
- Go tests, frontend type-check and six unit tests, Chromium/Firefox/WebKit browser coverage, monitoring and streaming integration, and isolated offline package install/update/rollback/retention/password-recovery checks passed.
- `dist/release-validation-1.3.6.json` records `local_gate: passed`, `release_readiness: ready`, and all required actual-host checks passed using the version-matched evidence in `docs/release-host-checks-v1.3.6.json`.
- The package was built from product source commit `0bb612060b2b`: `dist/jellyfin-proxy-1.3.6-linux-amd64.tar.gz`, 71,554,425 bytes, SHA-256 `0cf95dd64657a0d1f8f7a731600a7dea66b132fdd7a04c3c30f4c3c6c8848fba`. A matching `.sha256` file was generated. Subsequent `dev` commits through this record changed documentation only.
- PR #63 promoted the tested `dev` tree to `main` at merge commit `659ad837e9daa07608dbae4556930f81a26c8ad8`. The packaged product source is `0bb612060b2b`; the later changes through promotion were documentation-only.
- The `v1.3.6` GitHub tag and release assets have not yet been published. The archive and matching `.sha256` are available locally under `dist/`.

### v1.4.0-dev Fail2ban and security management — 2026-10-17

- **Focused package command:** `pwsh -NoProfile -File
  packaging/package.ps1 -Version 1.4.0-dev` — PASS, exit 0. The archive loaded
  all seven images into an isolated Docker daemon without registry access.
  Install, namespace firewalls, security/monitoring startup, v1.3 data
  preservation, update, rollback, retention, and password recovery passed.
  Its expected port-collision scenario verified failed-start cleanup.
- **Full release command:** `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.4.0-dev` — PASS, exit 0. Go tests, all M1–M6 integration checks,
  Chromium/Firefox/WebKit admin checks (4 tests), frontend typecheck, six
  frontend tests, production build, isolated Fail2ban/nftables IPv4/IPv6
  enforcement, signed admin-event processing/recovery, Caddy admin-only
  blocking and Jellyfin isolation, streaming/range/WebSocket regressions, and
  offline package/install/update/rollback gates passed.
- **Corrected attempts:** The initial full release attempt failed because the
  package check assumed two Alpine utility image references after v1.4 added
  init services. A follow-up exposed CRLF parsing in that check. The validator
  was fixed to parse image lines without matching across line endings; the
  package-only run and final complete release gate then passed.
- **Package:** `dist/jellyfin-proxy-1.4.0-dev-linux-amd64.tar.gz`, SHA-256
  `bfe06b37fc7da19bdf8bef694751c53872c61ef12a87d73843b46111e6656a77`.
  Report: `dist/release-validation-1.4.0-dev.json` (`local_gate: passed`,
  `release_readiness: blocked_host_checks_pending`).
- **Host checks:** Actual Ubuntu journald access, host-level SSH nftables,
  reboot recovery, public ACME/provider firewall, and native Windows
  WireGuard/firewall checks remain BLOCKED; this run did not use an actual VPS
  or Windows client.
- **Deployment/publication:** Neither was performed.

### v1.4.1-dev initial VPS deployment and restart bug reproduction — 2026-10-18

- **Local gate:** `pwsh -NoProfile -File .\build.ps1 release
  -Version 1.4.1-dev` passed on product commit `8a758f2` before PR #68 was
  merged. PR #68 changed only integration-test fixtures and timing. The
  post-merge `build.ps1 package` rerun on `418d981` stopped at a Playwright
  desktop screenshot height mismatch (expected 1440x3241, received 1440x3287);
  this is not recorded as a passing rerun. The deployed admin image reports
  source revision `418d981f477a`.
- **Package:** `dist/jellyfin-proxy-1.4.1-dev-linux-amd64.tar.gz`,
  124,850,758 bytes, SHA-256
  `28006722b800f04a8fe50ad286d27ce0ba09d48c623dbd1b2540c4ecee81efce`. The
  transferred checksum matched on the VPS.
- **VPS update:** `proxyctl update` completed successfully to `1.4.1-dev`; the
  updater verified persistent TOTP storage, loaded all seven images, validated
  configuration, activated the release, and reported healthy services. The
  active and previous releases are retained. All six containers (admin,
  Caddy, WireGuard, hostmetrics, securityd, and containerhealth) were healthy
  after update and after a full VPS reboot. Image labels report version
  `1.4.1-dev` and revision `418d981f477a`.
- **Swap and resource recovery:** Before adding swap, the host reported 833 MiB
  RAM, no swap, and 3.4 GiB free on `/`. The first Docker image import remained
  at 37% for about 15 minutes and was stopped before release activation. A
  2 GiB `/swapfile` was created with `fallocate`, `mkswap`, and `swapon`; the
  `/etc/fstab` entry `/swapfile none swap sw 0 0` and
  `/etc/sysctl.d/99-local-swap.conf` (`vm.swappiness=10`) make it persistent.
  The retry completed successfully. After reboot, `swapon --show` confirmed
  2 GiB active with about 84 MiB used; later checks showed about 96 MiB used.
  The root filesystem had 1.5 GiB available after deployment.
- **Host journal and Fail2ban:** From `securityd`,
  `journalctl --no-pager --output=short-iso -n 5 _COMM=sshd` returned actual
  host sshd records, including the post-reboot listener. Fail2ban reported
  exactly `jp-admin` and `jp-ssh`; `jp-admin` uses `jp-noop`. The host nftables
  chain `inet jp_fail2ban jp_ssh_input` contained the exact TCP/22 IPv4 and
  IPv6 drop rules. Reserved documentation addresses `192.0.2.123` and
  `2001:db8::123` were added to their corresponding SSH sets and then unbanned;
  both sets were empty afterward. After reboot the chain had one rule per
  address family. Before reboot, duplicate identical rule pairs were observed
  after service replacement; the clean reboot recreated one pair. Restart
  idempotence was later checked directly; the restart reproduced a duplicate
  pair as detailed below.
- **Public routes and reboot:** After reboot, ordinary DNS resolution reached
  the VPS; normal TLS verification returned `darkcry.com` 200,
  `admin.darkcry.com` 200, and `access.darkcry.com` 403, each with
  `ssl_verify_result=0`. `systemctl reboot` returned successfully; swap,
  services, host journal access, Fail2ban, and the SSH nftables chain recovered.
- **Restart idempotence check:** Before the restart, the host chain contained
  one IPv4/IPv6 TCP/22 drop-rule pair. `docker restart
  jellyfin-proxy-securityd-1` returned the container to healthy status within
  10 seconds, but added a second identical pair (nftables handles 6 and 7).
  Those two new rules were deleted by handle, leaving original handles 3 and 5
  in place. A new authenticated SSH connection succeeded; the container was
  healthy and the chain still contained exactly one pair. This reproduced the
  restart idempotence defect on 1.4.1-dev.
- **Windows and report status:** The peer's latest-handshake value was `0`
  immediately after reboot. The operator subsequently confirmed that streaming
  works after this deployment. The machine-readable full-release report
  predates this deployment and still contains the earlier blocked host-check
  results; it was not regenerated.
- **Restart fix and local gates:** `nftables-common.local` now lists each
  nftables object before adding it and adds each address-family rule only when
  absent. `security-firewall.ps1` asserts one IPv4 and one IPv6 rule at startup,
  kills the Fail2ban process without its cleanup action, restarts Fail2ban in
  the same network namespace, and asserts the rule pair remains singular while
  ban/unban behavior continues to work. The focused `security-firewall.ps1`,
  `build.ps1 test`, and `build.ps1 release -Version 1.4.1-dev` all passed on the
  working tree. The preliminary package had a `-dirty` revision label and was
  not deployed. The clean 1.4.2-dev gate and host retest are recorded below.

### v1.4.2-dev restart fix release and VPS verification — 2026-10-18

- **Source:** Commit `1b1f6ab5d4d8b3deb61158d60fa1cd1b26cb213c` on
  `fix/securityd-nftables-restart-idempotence`.
- **Release gate:** `pwsh -NoProfile -File .\build.ps1 release -Version
  1.4.2-dev` — PASS, exit 0. Go tests, Firefox/WebKit/Chromium browser checks,
  full v1.4 integration including Jellyfin streaming and WireGuard recovery,
  restart-idempotent isolated nftables regression, and offline package
  install/update/rollback/retention/password-recovery checks passed. The
  generated report records the local gate as passed and host checks as blocked;
  it was not regenerated with the subsequent VPS results or native Windows
  evidence.
- **Package:** `dist/jellyfin-proxy-1.4.2-dev-linux-amd64.tar.gz`, 124,849,163
  bytes, SHA-256
  `b1b518f426e19b36271dce50fbc0edd662a003516d51bca06b6d6bc661c0fee4`.
  The uploaded package checksum matched before installation. The standalone
  updater checksum also matched the local artifact.
- **VPS update:** The documented `proxyctl update` completed successfully to
  `1.4.2-dev`; all six services were healthy afterward. Persistent data and the
  previous release were retained by the updater.
- **Host restart regression:** Before restart, the live host chain had one
  IPv4 and one IPv6 TCP/22 drop rule (handles 3 and 5). After each of two
  consecutive `docker restart jellyfin-proxy-securityd-1` operations, the
  chain still contained exactly those two rules, with counts IPv4=1 and IPv6=1.
  Both `jp-ssh` and `jp-admin` jails were active after the restarts. A separate
  new SSH connection succeeded; all six containers remained healthy.
- **Public routes:** From the VPS after the restarts, normal certificate
  verification returned `darkcry.com` HTTP 200, `admin.darkcry.com` HTTP 200,
  and `access.darkcry.com` HTTP 403, all with `ssl_verify_result=0`.
- **Windows streaming:** The operator confirmed streaming on 1.4.1-dev. This
  change is limited to Fail2ban/nftables startup; native Windows playback was
  not repeated on 1.4.2-dev.
- **Publication:** No stable v1.4 release was created or published.
- **Integration:** [PR #69](https://github.com/Mytob/project_j/pull/69) merged
  the fix and verification records into `dev` at merge commit `eebe308`.
