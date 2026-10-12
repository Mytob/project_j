# Architecture

This document distinguishes the frozen 1.0 target from the currently
implemented M1 local test environment.

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

## M1 local environment

The local integration Compose project is under `tests/integration/`. Caddy
serves `domain.test`, returns an explicit not-yet-implemented response for
`admin.domain.test`, and enforces a generated allowlist policy before
reverse-proxying `access.domain.test` to a small Go mock of Jellyfin. An empty
list generates only a 403 handler. Caddy uses its internal test CA. Only
Caddy's HTTP and HTTPS ports are published, bound to loopback. The mock has no
host port. The test uses two isolated source addresses to prove CIDR allow,
default deny, and rejection of spoofed forwarding headers.

This is not a production deployment and does not establish public certificate,
whitelist, admin, or WireGuard behaviour.

## Trust and security boundaries

- Caddy is the only public HTTP entry point.
- Client identity is the socket peer address; forwarding headers are not
  trusted for access decisions.
- The whitelist is default deny, including when empty or invalid.
- Caddy's administration API is private and unavailable on public interfaces.
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

The admin application will update validated Caddy configuration through its
private Unix admin socket. A whitelist change is persisted and activated as a
transaction: failures preserve the last valid active configuration and are
reported as failures. No public admin API or Docker socket is used.
