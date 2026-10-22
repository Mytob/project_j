# v1.6 isolated VPS acceptance checklist

This checklist is for a **separate disposable VPS and test domain** after a
clean `1.6.0` release package has passed the local and Ubuntu VM gates. Do not
use the production Jellyfin Proxy host or its domains for installation,
upgrade, rollback, firewall, restore, or failure-injection testing. Record only
observed results and redact credentials, tokens, private keys, and backup
contents.

The clean-tree 1.6.0-dev.19 candidate passed the local release gate and an
exact-package update from dev.18 on a disposable Ubuntu VM. Its checksum,
pre-update backup, service/HTTPS readiness, version-matched doctor, five
container health checks, and default error-page migration passed. It remains a
development candidate, not a stable release. Do not deploy it to the
production VPS. Public acceptance was performed on the user-authorized
disposable public VPS and is recorded below. This remains a development test
host, not production acceptance or a stable release.

## Before installation

- [x] VPS is disposable, Ubuntu Server 26.04.1 LTS x86-64, and had no data that
  needs preserving.
- [ ] Provider-console access works and a recovery route is available if SSH
  or the host firewall is misconfigured.
- [ ] Record comparable baseline CPU, memory, swap, disk, and network usage.
  Initial memory, swap and disk were noted; comparable workload measurements
  were not taken.
- [x] Point base, admin, and access hostnames at this VPS; external HTTPS
  requests reached all three names.
- [ ] Confirm the provider firewall allows only required ingress: TCP 22, 80,
  and 443; UDP 51820 only when the WireGuard endpoint is enabled. Keep Jellyfin
  TCP 8096 private to the tunnel.
- [x] Record the release version, build identifier, package SHA-256, standalone
  `proxyctl` SHA-256, and supported source versions from an independently
  obtained release page. See [TESTING.md](../TESTING.md).

## Fresh installation

- [x] Transfer the `.pkg` and sidecar checksums to the VPS; verify them before
  starting the installer.
- [x] Complete the full-screen installer over SSH, including resource and
  capability checks, domain review, administrator/allowlist configuration,
  backup policy, and final review.
- [x] Confirm any Docker/prerequisite installation is explicitly approved.
- [x] Confirm a separate administrator can sign in and use `sudo` before any
  root SSH restriction is applied; retain provider-console recovery.
- [ ] Confirm firewall changes preserve unrelated rules and the installer does
  not expose Docker, Caddy administration, Jellyfin, or the monitoring
  collector publicly. External probes found the tested ports unreachable and
  Docker publishes only 80/443 and UDP 51820. The provider rules were not
  reviewed after the rebuild.
- [x] Verify the installer reports completion only after all managed services
  and public HTTPS are ready. Run `proxyctl doctor` and record every
  result.
- [x] Confirm all expected containers are healthy, maintenance and scheduled
  backup units are active, and the host SSH journal is readable by the
  restricted security service.

## Public routes and security

- [x] From an external network, verify valid publicly trusted TLS for the base
  and admin hostnames and the expected default-deny response for the access
  hostname.
- [ ] Verify the admin allowlist blocks an untrusted address and permits only
  the configured administrator address; test IPv4 and IPv6 when both are
  enabled.
- [ ] Confirm the provider firewall and host nftables rules agree, and that
  SSH protection has the expected Fail2ban jail and exact-address ban/unban
  behavior. The host jails and IPv4/IPv6 ban/unban passed; provider comparison
  remains pending.
- [x] Confirm no host or collector metrics port, Docker socket, Caddy admin
  endpoint, or Jellyfin TCP 8096 is reachable from the public internet.
- [ ] Verify Caddy obtains a trusted certificate and renews it using the
  documented ACME flow. Use an isolated test hostname and respect CA rate
  limits; do not force production renewals on an unrelated domain. Initial
  public TLS passed; renewal was not tested.

## WireGuard and Jellyfin

- [ ] Import the one-time Windows profile on a designated Windows test client;
  confirm the server-side downloadable copy is removed after transfer.
- [ ] Apply and inspect the scoped Windows inbound rule: TCP 8096 only from the
  WireGuard server tunnel address; remove or disable broader Jellyfin rules.
- [ ] Verify a recent peer handshake and bidirectional counters on the VPS.
- [ ] Confirm Jellyfin `/health` and real playback through the public proxy over
  the tunnel; verify Jellyfin remains unreachable directly from the internet.
- [ ] Reboot the Windows test host and VPS separately; verify the tunnel and
  playback recover without exposing additional ports.

## Backup, update, and operations

- [ ] Create a manual `.bak`; verify its checksum, manifest, required files,
  SQLite consistency, restrictive permissions, and authenticated download.
- [ ] Confirm the scheduled backup runs and retention removes only expired
  application backups.
- [ ] Review `proxyctl host-update` proposals without approving them; confirm
  it never schedules unattended OS/Docker/application updates or reboots.
- [ ] On this disposable host, install a compatible package update through the
  dashboard and CLI in separate runs; confirm checksum entry, compatibility
  review, durable progress, mandatory verified pre-update backup, health checks,
  and previous-release rollback.
- [ ] Exercise repair after an interrupted operation only with a verified
  backup and provider-console access available. Do not inject failures on a
  production host.
- [ ] Confirm dashboard backup, restore, package, retention, storage, About,
  Health, and Web Content workflows match the installed release.
- [ ] Record CPU, memory, disk, and network usage after steady-state operation;
  compare with the pre-install baseline under the same workload.

## Result record

| Check | Result | Evidence / date |
| --- | --- | --- |
| Release and checksums | PASS | dev.19 package and standalone proxyctl sidecars verified; 2026-10-22 |
| Fresh install and recovery access | PASS | Installer, alternate SSH admin/sudo, doctor and post-reboot recovery passed; 2026-10-22 |
| Provider firewall, DNS, public TLS | PARTIAL | Public HTTPS 200/200/403 with verified TLS; provider rules and ACME renewal not inspected/tested; 2026-10-22 |
| Host firewall, Fail2ban, journal | PARTIAL | Fail2ban jails, host journal and IPv4/IPv6 nftables ban/unban passed; host UFW inactive and provider comparison pending; 2026-10-22 |
| Windows WireGuard and Jellyfin playback | PENDING | No Windows import, peer handshake, scoped firewall or playback check; operator to perform |
| Backups, update, rollback, repair | PARTIAL | Manual CLI backup verified; dashboard update/rollback, authenticated download, scheduled execution and repair not tested on public VPS; 2026-10-22 |
| Resource measurements | PARTIAL | Install and post-reboot disk/swap observed; no comparable steady-state workload sample; 2026-10-22 |

Passing this checklist is environment-specific deployment acceptance. It does
not replace the local release suite, disposable Ubuntu failure tests, or
security review.
