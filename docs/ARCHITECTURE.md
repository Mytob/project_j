# Architecture

This document distinguishes the frozen 1.0 target, the M1–M6 local test
environment, and the M8 Ubuntu installer implementation.

## Target components and request path

```text
Internet clients
       |
       v
VPS public TCP 80/443 -> Caddy (shares WireGuard network namespace)
                              |             |
                  base site   |             +-- admin.domain.com -> Go admin
                              |
                  access.domain.com -> whitelist -> WireGuard -> Windows Jellyfin
```

The VPS target has three main containers: Caddy, WireGuard, and the Go admin
application. Docker Compose gives Caddy the WireGuard service's network
namespace. The WireGuard container owns published web and tunnel ports. The
admin container remains separate and can reach Caddy's admin API only over a
private Unix socket with narrowly scoped filesystem permissions. It never
receives Docker socket access. All services use `restart: unless-stopped`.

The installer publishes TCP 80/443 and the selected host UDP port from the
WireGuard namespace. Since Docker DNAT may bypass the host INPUT firewall, the
WireGuard entrypoint owns dedicated IPv4 and IPv6 namespace INPUT chains:
established traffic and loopback are accepted, as are the expected IPv4 Windows
peer and the three application service ports; all other ingress is dropped.
This leaves host SSH and unrelated host firewall rules alone. It does not
configure a provider firewall/security group; those ports must be allowed there
by the operator.

## M1–M6 local environment

The local integration Compose project is under `tests/integration/`. Caddy
serves `domain.test`, proxies `admin.domain.test` to the Go admin service, and
enforces a generated allowlist policy before
reverse-proxying `access.domain.test` to a small Go mock of Jellyfin. An empty
list generates only a 403 handler. The admin service owns a versioned JSON
allowlist and submits a complete Caddyfile through a permissioned Unix socket;
failed activation restores the prior persisted list, and failed persistence
does not activate the candidate policy. Caddy has no public admin TCP listener.
Caddy uses its internal test CA. Only
Caddy's HTTP and HTTPS ports are published, bound to loopback. The mock has no
host port. The test uses two isolated source addresses to prove CIDR allow,
default deny, and rejection of spoofed forwarding headers. The admin service
loads a single file-based password credential, serves server-rendered sign-in
and dashboard pages, rotates opaque in-memory sessions at login, expires them
after 12 hours, protects state-changing forms with CSRF, and throttles repeated
failed attempts. TOTP setup is server-rendered: an administrator re-enters the
password before the service reveals a pending secret and locally generated QR
PNG. That password check grants five minutes of setup visibility. A six-digit
code must confirm setup; cancellation returns to the unconfigured state, and
activation revokes all sessions. No QR service or frontend runtime is used.
The admin application runs as a non-root user, its test-only
credential fixture is disposable, and its service port is private to the
Compose network.

For M5, the WireGuard server container owns the test HTTP/HTTPS host bindings
and shares its network namespace with Caddy. A separate home-peer container
initiates the WireGuard tunnel. The mock Jellyfin service shares the home
peer's namespace and listens only on the peer's tunnel address; the integration
runner verifies the encrypted path, loss of reachability on tunnel shutdown,
and recovery after a fresh peer handshake. The test config-init service copies
the generated pair into isolated named volumes: the server private key remains
root-only and only the Windows peer config is readable by the non-root admin
group for authenticated downloads. The peer file uses persistent `/32` routes
and a 25-second keepalive; the real Windows config and server config are
retained together by the WireGuard package and are not regenerated on restart.

The M1–M6 test environment is not a production deployment. M8's actual package
is installed in an isolated Docker-in-Docker daemon and its namespace firewall
is inspected there; this does not establish public certificate issuance,
provider firewall settings, public ingress, or Ubuntu VPS WireGuard behaviour.

## Trust and security boundaries

- Caddy is the only public HTTP entry point.
- Client identity is the socket peer address; forwarding headers are not
  trusted for access decisions.
- The whitelist is default deny, including when empty or invalid.
- Caddy's administration API is a permissioned Unix socket mounted only into
  Caddy and the admin container; no public TCP listener is configured.
- WireGuard private keys and generated client config are sensitive persistent
  data with restricted permissions.
- Administrator TOTP secrets are stored as AES-256-GCM ciphertext in the
  writable admin data mount. A separately generated 256-bit key is kept in the
  root-owned, read-only config mount; neither file is included in a release.
- Missing or invalid TOTP key/state files prevent the admin process from
  starting. An explicitly initialized unconfigured state is distinct from a
  missing state file, so deletion cannot silently turn TOTP off.
- Admin sessions, CSRF protection, password hashing, and non-cacheable config
  download are owned by the Go admin application.
- Installation/update code preserves persistent data and scopes cleanup to
  application-owned artifacts.

## Configuration ownership and persistence

The planned install root is `/opt/jellyfin-proxy/` with `config/`, `data/`,
`site/`, `releases/`, and `compose.yaml`. Deployment config is validated and
written atomically. The updater stages and verifies each release before
replacing active environment, Compose, and Caddy template files. It preserves
credentials, whitelist state, WireGuard keys, the separate TOTP key/state,
and site content, then verifies service and HTTPS readiness. TOTP state is
written mode 0600 under the app-owned mode 0700 data directory; the key is
root-owned, readable by the dedicated admin group, and mounted read-only.
The v1.0 migration creates both TOTP files only when neither exists; partial
or corrupt state fails closed. Backups must retain the key and state together.
On update failure the updater restores the previous files and recreates the
previous services. It retains the active and previous version directories,
deleting only older versioned directories after success. The current M1 test
files live in the repository and create no deployment data.

## Module boundaries

The Go module has separate commands under `cmd/`. Domain and adapter code will
live in focused packages under `internal/`: authentication, configuration,
whitelist, WireGuard config, deployment, firewall preflight, and release
handling. Packages are introduced with their behaviour, not as empty
scaffolding. The M1 mock uses the Go standard library only.

## WireGuard routing

The Windows client initiates a persistent-keepalive peer connection to the
VPS. Split routes carry only the VPS-to-Windows WireGuard address and Jellyfin
TCP traffic over the tunnel. Home internet routing, LAN routes, and router
port forwarding are excluded. The VPS targets the Windows peer address on
Jellyfin port 8096 by default.

## Caddy and admin communication

The admin application updates validated Caddy configuration through its
private Unix admin socket. It persists a candidate allowlist first, then
activates it through Caddy's transactional `/load` endpoint; if activation
fails it restores the previous persisted list. A persistence failure leaves
the active Caddy policy untouched. No public admin API or Docker socket is
used.

The socket address and permission syntax follow Caddy's
[admin endpoint configuration](https://caddyserver.com/docs/caddyfile/options).
The admin service submits adapted configuration to the documented
[`POST /load` endpoint](https://caddyserver.com/docs/api), which keeps the
previous active configuration if the new config cannot be loaded.
