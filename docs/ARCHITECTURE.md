# Architecture

This document distinguishes the frozen 1.0 target from the currently
implemented M1–M5 local test environment.

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

## M1–M5 local environment

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
failed attempts. The admin application runs as a non-root user, its test-only
credential fixture is disposable, and its service port is private to the
Compose network.

For M5, the WireGuard server container owns the test HTTP/HTTPS host bindings
and shares its network namespace with Caddy. A separate home-peer container
initiates the WireGuard tunnel. The mock Jellyfin service shares the home
peer's namespace and listens only on the peer's tunnel address; the integration
runner verifies the encrypted path, loss of reachability on tunnel shutdown,
and recovery after a fresh peer handshake. Generated keys are disposable test
fixtures and are deleted during cleanup.

This is not a production deployment and does not establish public certificate,
production file ownership, public admin operation, public UDP ingress, or
Ubuntu VPS WireGuard behaviour.

## Trust and security boundaries

- Caddy is the only public HTTP entry point.
- Client identity is the socket peer address; forwarding headers are not
  trusted for access decisions.
- The whitelist is default deny, including when empty or invalid.
- Caddy's administration API is a permissioned Unix socket mounted only into
  Caddy and the admin container; no public TCP listener is configured.
- WireGuard private keys and generated client config are sensitive persistent
  data with restricted permissions.
- Admin sessions, CSRF protection, password hashing, and non-cacheable config
  download are owned by the Go admin application.
- Installation/update code preserves persistent data and scopes cleanup to
  application-owned artifacts.

## Configuration ownership and persistence

The planned install root is `/opt/jellyfin-proxy/` with `config/`, `data/`,
`site/`, `releases/`, and `compose.yaml`. Deployment config is validated and
written atomically. The updater may replace active release files and compose
templates, but not user data, credentials, whitelist state, WireGuard keys, or
website content. The current M1 test files live in the repository and create
no deployment data.

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
