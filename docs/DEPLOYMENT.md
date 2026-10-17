# Deployment

## Supported target

- Ubuntu 26.04 LTS, x86_64, with root access through `sudo`.
- A VPS with a public IPv4 and/or IPv6 address and inbound TCP 80/443 plus a
  chosen UDP WireGuard port allowed by its provider firewall/security group.
- Three DNS names pointing to the VPS: the base domain, `admin.<domain>`, and
  `access.<domain>`.
- A Windows 11 Jellyfin host with the official WireGuard client.
- Docker Engine and Compose v2. If Docker is absent, `proxyctl` can install it
  from Docker's official Ubuntu APT repository after operator confirmation.

The installer reports the addresses returned by DNS and asks the operator to
confirm them. It cannot infer a VPS's public/NAT address. It refuses unsupported
OS versions/architectures, non-root execution, an existing `/opt/jellyfin-proxy`
directory, or existing Docker resources for the `jellyfin-proxy` Compose
project. It does not overwrite an earlier installation.

## Install

Build or obtain the matching Linux/amd64 package and standalone installer. Copy
both to the VPS, then run from an interactive terminal:

```sh
sudo ./proxyctl-linux-amd64 install ./jellyfin-proxy-1.0.0.tar.gz
```

The guided prompts collect the base domain, confirmation of the displayed DNS
records, a password (hidden input, 12 or more characters), and the public UDP
port (default 51820). The installer then validates the package, lays out
`/opt/jellyfin-proxy/`, generates retained WireGuard peer configurations,
loads only the package's verified images, starts the fixed Compose project and
waits for healthy services and public HTTPS on the base domain. An empty
whitelist is installed, so the Jellyfin access hostname denies all clients
until an administrator adds allowlist entries.

The install is deliberately non-destructive: it refuses to reuse an existing
install or project. If startup or readiness fails, it stops only the new
`jellyfin-proxy` Compose project, removes its generated volumes and files, and
reports the failing stage. It does not globally prune images or alter other
Compose projects. Docker Engine/Compose installation, if selected, is a
separate system package operation and is not rolled back.

The installed directories are:

```text
/opt/jellyfin-proxy/
├── config/       # admin credentials, Caddy config, retained WireGuard peers
├── data/         # persistent whitelist and encrypted administrator TOTP state
├── site/         # persistent base-domain website
├── releases/     # verified package archive contents by version
├── compose.yaml
└── .env
```

The installer also creates `config/totp.key` as an independent random
256-bit key. It is owned by root, readable by the admin container's dedicated
group, and mounted read-only. `data/totp-state.json` stores pending or active
authenticator material encrypted with AES-256-GCM; it is owned by the admin
container and mode 0600 inside the mode 0700 data directory. The key is not
stored in or derived from the encrypted state.

The admin process fails closed if either file is missing, has unsafe
permissions, or cannot be validated. A v1.0 update creates both files only
when neither exists. A partial pair or corrupt state stops the update rather
than treating TOTP as unconfigured. For backup and restore, preserve
`config/totp.key` and `data/totp-state.json` together. Restoring only one will
prevent the admin service from starting. Neither file is included in release
packages.

Release images include the package version and source commit build number;
both are shown in the authenticated admin dashboard.

## VPS firewall and ports

Docker publishes TCP 80/443 and the selected host UDP port from the WireGuard
container's network namespace. Docker DNAT can bypass the host's normal INPUT
firewall chain, so the WireGuard container installs IPv4 and IPv6 ingress
filters in that namespace. They permit established traffic, loopback, TCP
80/443, and UDP 51820 inside the container, then drop other ingress; the IPv4
filter also permits the expected Windows peer. The published host UDP port maps
to container UDP 51820. This does not edit UFW,
nftables, host iptables, the SSH port, or unrelated Docker resources; it also
does not disable an existing host/provider firewall. Ensure the provider
firewall/security group permits the three published services. If a host-level
policy already blocks Docker forwarding, configure that policy using your VPS
provider's supported procedure while preserving SSH access.

The namespace rule is installed on each WireGuard container start. The Windows
peer is assigned `10.66.66.2`; the VPS peer is `10.66.66.1`.

## Update and password reset

Copy the new self-contained package and `proxyctl-linux-amd64` to the VPS, then
run:

```sh
sudo ./proxyctl-linux-amd64 update ./jellyfin-proxy-1.0.1.tar.gz
```

The updater reports its completed milestones as a percentage. A live spinner
and elapsed time remain visible while Docker loads images or the health checks
wait; non-interactive output emits periodic wait messages. The percentage
tracks completed stages, not Docker's byte-level work. The updater verifies the
release manifest and bundled image digests, refuses version downgrades, loads
images without registry pulls, and recreates only the `jellyfin-proxy` services.
It preserves the administrator credential,
whitelist, WireGuard keys, TOTP key and encrypted state, and all site files.
After healthy services and public HTTPS are verified,
it retains the new active release and the immediately previous release and
removes only older versioned release directories. It does not prune Docker
images. If updated readiness fails, the prior Compose files and version are
restored and the previous services are recreated; inspect the reported rollback
error and scoped service logs if recovery cannot become healthy.

To set a new administrator password locally from an interactive root shell:

```sh
sudo ./proxyctl-linux-amd64 reset-password
```

The new password is entered twice with terminal echo disabled. The command
replaces the hashed credential atomically, restores its restricted ownership
and permissions, and recreates only the admin service. Admin sessions are
in-memory, so this restart invalidates every existing session. If the new admin
container does not become healthy, the previous credential is restored.

Lost-authenticator recovery is available only from a local root shell on the
VPS. These commands never change the administrator password:

```sh
sudo ./proxyctl-linux-amd64 reset-totp
sudo ./proxyctl-linux-amd64 replace-totp
sudo ./proxyctl-linux-amd64 disable-totp
```

`reset-totp` is the emergency recovery path. It invalidates the old factor,
recreates only the admin service (which invalidates all in-memory sessions),
and requires a new authenticator enrollment after the existing password is
entered. Until that enrollment is verified, the session is limited to setup and
sign-out; cancelling returns to the same required-enrollment state. `replace-totp`
does the same when an authenticator is currently enabled. The new factor is not
active until its six-digit code verifies successfully. `disable-totp` clears
authenticator state and returns to password-only administrator login. Each
command validates the installed state, and a failed state update or admin
restart restores the prior state and restarts the prior admin service. The
local recovery commands require root. To disable an authenticator during
normal operation, open the administrator dashboard, expand **Disable
two-factor authentication**, and submit the administrator password plus a
current unused authenticator code. This clears the factor and signs out every
admin session. The dashboard also shows the running release version and source
commit build number.

## First login and Windows WireGuard

1. Open `https://admin.<domain>` and sign in with the initial password.
2. In the dashboard's administrator authenticator section, re-enter the
   administrator password, scan the locally generated QR code (or enter its
   secret manually), then submit a six-digit authenticator code to activate
   TOTP. Activation signs out every administrator session.
3. Sign in again with both the administrator password and a current unused
   authenticator code. Every new administrator login requires both factors.
4. Download the Windows WireGuard configuration once from the authenticated
   admin dashboard. The server removes its private copy after the complete
   transfer. The download uses split-tunnel `/32` routes and a 25-second
   persistent keepalive. Regeneration becomes available only after the
   download completes.
5. Import it into the official WireGuard client on the Windows Jellyfin PC and
   activate the tunnel.
6. Add only the desired public client IP addresses/CIDRs to the access
   whitelist. An empty list is default deny.
7. Restrict the Windows Jellyfin inbound firewall rule to TCP port 8096 from
   the VPS WireGuard address `10.66.66.1`. In an elevated PowerShell window on
   Windows, a narrow example rule is:

   ```powershell
   New-NetFirewallRule -DisplayName "Jellyfin from VPS WireGuard" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8096 -RemoteAddress 10.66.66.1 -Profile Any
   ```

   Review existing broad Jellyfin allow rules and disable those that would
   allow other remote sources. Do not configure home-router port forwarding or
   LAN routes for this deployment.

## Verification

- Confirm all three names resolve to this VPS before installation.
- Confirm `https://<domain>/` shows the static site and has a publicly trusted
  certificate.
- Sign in at `https://admin.<domain>`, download the Windows config once, and
  confirm the stored copy disappears and peer regeneration becomes available.
  A second download must be rejected; regeneration must remain unavailable
  until the first transfer completes.
- With the Windows peer active, confirm its handshake is recent and add a
  temporary allowed client to verify Jellyfin access through
  `https://access.<domain>`.
- Remove the temporary entry and confirm access returns to HTTP 403.
- Confirm Jellyfin is not published directly on a VPS port and its Windows
  firewall rule accepts only the VPS tunnel address.

Useful status/log commands:

```sh
cd /opt/jellyfin-proxy
sudo docker compose --project-name jellyfin-proxy --file compose.yaml --env-file .env ps
sudo docker compose --project-name jellyfin-proxy --file compose.yaml --env-file .env logs --tail=100
sudo docker compose --project-name jellyfin-proxy --file compose.yaml --env-file .env exec wireguard wg show
```

## Troubleshooting and limits

- **DNS check fails:** create/repair the base, `admin`, and `access` records;
  check both A and AAAA records point to this VPS.
- **Compose cannot bind a port:** stop or reconfigure the service already using
  TCP 80/443 or the selected UDP port, then retry. The installer cleans up its
  partial deployment and will not stop that other service.
- **Services never become healthy:** inspect the scoped Compose logs and verify
  the VPS kernel supports WireGuard and Docker permits `NET_ADMIN`.
- **Public HTTPS check fails:** verify provider firewall rules, DNS, inbound
  TCP 80/443, and that the base domain is reachable from the VPS itself. The
  installer rolls back its application files and Compose resources on failure.
- **No WireGuard handshake:** verify UDP ingress at the provider and host,
  endpoint/port in the downloaded Windows config, and Windows outbound policy.
- **Tunnel works but Jellyfin does not:** verify the Windows peer is active,
  Jellyfin listens on the tunnel address/port, and its inbound firewall permits
  TCP 8096 from `10.66.66.1`.
- **Access stays denied:** add the client's actual public address/CIDR; the
  service does not trust forwarded client-IP headers or CDN proxy addresses.

The automated installer gate runs the actual release package in an isolated
Docker-in-Docker daemon, validates namespace firewall rules, and exercises a
fresh install plus failure rollback. It does not prove public ACME issuance,
VPS-provider firewall behavior, or the Ubuntu 26.04 host/kernel path. Validate
those on the actual VPS before treating a deployment as production verified.
