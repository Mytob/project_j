# Deployment

Production installation is not yet implemented. The instructions below define
the intended 1.0 operator path and must be converted into executable guidance
and `proxyctl` checks before release.

## Target prerequisites

- Ubuntu 26.04 LTS x64 VPS with public IPv4 and/or IPv6.
- Docker Engine and Docker Compose plugin.
- Domain DNS control and three hostnames pointing to the VPS.
- Windows 11 Jellyfin host with the official WireGuard client.
- An SSH account with sudo access; the installer must preserve its SSH port.

## Intended installation

1. Verify host release, architecture, privileges, Docker, Compose, and DNS.
2. If Docker is absent, offer installation through Docker's official APT
   repository.
3. Run the versioned native `proxyctl` package installer.
4. Set the base domain and initial administrator password using hidden input.
5. Generate WireGuard server/client config and deploy bundled images.
6. Leave the Jellyfin whitelist empty (default deny).
7. Verify service health and readiness before reporting success.

Install files are planned under `/opt/jellyfin-proxy/`; config, data, site,
releases, and Compose state are separate. Do not publish the local M1 test
Compose project to the Internet.

## Windows WireGuard and firewall

The final release will provide an authenticated downloadable `.conf` for the
official Windows client. It will use split tunnelling and persistent keepalive.
The Windows firewall instructions will permit Jellyfin TCP traffic only from
the VPS WireGuard address. They will not add router forwarding or home LAN
routes.

## Verification and troubleshooting

Release deployment guidance must include DNS resolution, Caddy HTTPS
readiness, WireGuard peer health, access whitelist behaviour, Windows firewall
checks, and Jellyfin connectivity. It must distinguish VPS preflight from
local simulation. Concrete commands and recovery steps will be added when the
installer is implemented and tested.

Current blocker: no production deployment or host preflight code exists yet.
