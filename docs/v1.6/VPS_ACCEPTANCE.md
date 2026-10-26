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

The exact dev.27 package passed the local release gate and was updated on this
VPS on 2026-10-23. The updater created a verified dev.26 pre-update backup and
passed HTTPS readiness; `proxyctl doctor`, all five healthy containers, and
the maintenance service and scheduled backup timer passed. Verified external
TLS returned 200/200/403 for the base, admin, and access hostnames. Admin
crawler headers and robots rules were present, and the refreshed sign-in page
used generic “Admin / Control panel” wording. After sign-in, Overview showed
all 12 component states Healthy; Security showed 10 active bans with
pagination and a live countdown; and System showed the backup retention cap
and individual Delete controls. Provider firewall, ACME renewal, real-host
journal/nftables enforcement, and native Windows acceptance remain open.

The dev.30 candidate passed the local release gate on 2026-10-24. After
operator sign-in, the VPS was observed on dev.29. Its `/tmp` tmpfs was 405 MB
and package uploads occupied 792 MB. After older backups were deleted, a
persistent systemd `tmp.mount` drop-in raised the limit to 1 GiB. The corrected
dev.30 package passed checksum and compatibility review for Ubuntu
26.04/amd64. Its mandatory pre-update backup completed (559,962,934 bytes),
the update installed dev.30, all five containers became healthy, and
`proxyctl doctor` passed. Public TLS checks returned 200/200/403. The admin
progress panel remained stale with “Maintenance progress is unavailable” after
the service restart; reloading returned to sign-in. Therefore live progress
recovery and dashboard rollback remain incomplete. The successful upload from
this work was removed after installation; older uploads and managed backups
were preserved.

The dev.31 candidate passed the full local release gate on 2026-10-24. The first
live attempt stopped safely when the dev.30 mandatory pre-update backup ran out
of space; the active release remained dev.30. Three older staged uploads were
preserved in temporary storage during the retry and restored with their original
contents and metadata afterward. The exact dev.31 package passed checksum and
compatibility review and installed successfully. Its mandatory dev.30 backup
was 284,213,886 bytes and passed `proxyctl verify-backup` with 44 files. Durable
job `545fbbea9d91691ce3de5f024a8fa383` survived the Admin restart and reached
`completed`, step 8/8, result dev.31. All five containers were healthy,
`proxyctl version` returned dev.31, and `sudo -n proxyctl doctor` passed all
checks. Admin showed a reconnect during restart,
then required sign-in again; the authenticated rendered result after sign-in
was not rechecked. A separate dev.31 backup was 7.0 MiB, verified with 40
files, and contained no `data/package-uploads` entries. Its temporary archive
was removed after verification. The three older uploads and existing managed
backups were preserved; our two dev.31 uploads were removed. The host had
352 MiB free (96% used) after restoration; safe unused-image cleanup removed
zero images. Remaining live progress UI after re-authentication, rollback,
public-host restore, real-host journal/nftables, provider firewall/ACME, and
native Windows checks remain open.

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
  The operator reported that playback works on 2026-10-22, but the client,
  route and supporting handshake/health observations were not recorded, so
  this combined check remains incomplete.
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
| Release and checksums | PASS | dev.30 package SHA-256 `B70028B8DB8C6DB9BFC65F4DFCF41E54683BE4D8FC5EFF8A886686E410CE3FC8` and dev.31 package SHA-256 `5DDEC178CAF7D008A61EA3D89D41B2CBF858A10CD51C3BF005ECED97ADFA40BD` passed live review; dev.31 installed on 2026-10-24 UTC |
| Authenticated admin pages | PARTIAL | dev.27 Overview showed all 12 components Healthy; Security pagination and live countdown advanced; System showed backup controls. After the dev.31 Admin restart, the page reconnected then required sign-in; the completed durable job was read over SSH, but its authenticated rendered result after sign-in remains unchecked. |
| Fresh install and recovery access | PASS | dev.19 fresh install/reboot and recovery access passed; dev.27 updater, doctor, five-container health and maintenance/backup units passed. Dev.30 updater and doctor passed; dev.31 updater, durable job, five-container health and `proxyctl doctor` passed; 2026-10-24 |
| Provider firewall, DNS, public TLS | PARTIAL | dev.30 external verified TLS returned 200/200/403. Provider rules and ACME renewal remain unverified; 2026-10-24 |
| Host firewall, Fail2ban, journal | PARTIAL | dev.19 host journal, Fail2ban jails and IPv4/IPv6 nftables ban/unban passed. dev.27 real-host journal/nftables/Fail2ban and provider comparison remain pending. |
| WireGuard and Jellyfin playback | PARTIAL | dev.25 Health reports Windows peer and Jellyfin endpoint healthy; tunnel/streaming integration passed. Native Windows playback, scoped firewall, and reboot recovery were not retested on dev.25. |
| Backups, update, rollback, repair | PARTIAL | Live dev.31 update completed with a 284,213,886-byte dev.30 pre-update backup verified with 44 files. A dev.31 test backup verified with 40 files (7.0 MiB) and no package-upload entries. Durable job state completed after the Admin restart; rendered status after re-authentication, rollback, public-host restore, and repair remain untested. |
| Resource measurements | PARTIAL | dev.25 Health showed CPU 5.1%, memory 515.6 MB of 809.3 MB, and 2.2 GB disk available; this single sample is not comparable steady-state workload evidence. |

Passing this checklist is environment-specific deployment acceptance. It does
not replace the local release suite, disposable Ubuntu failure tests, or
security review.
