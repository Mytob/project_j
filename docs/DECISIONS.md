# Frozen 1.0 decisions

The pasted implementation brief refers to 41 previously confirmed decisions,
but it does not contain a separate numbered list of those 41 decisions. This
record captures requirements that are explicitly stated in the brief and does
not invent missing decisions. Implementation details below are marked as such;
they do not reopen the stated requirements.

## Product and scope

1. Version 1.0 serves Jellyfin only.
2. The deployment path is Internet → Ubuntu VPS → WireGuard → Windows 11
   Jellyfin.
3. There are three hostnames: base, admin, and access.
4. The base hostname serves static website files directly through Caddy.
5. Website files persist across updates.
6. The admin hostname is publicly reachable over HTTPS and password protected.
7. There is one administrator account; no registration or multi-user system.
8. Admin state uses files, not a database.
9. The access hostname proxies Jellyfin.
10. Access uses a default-deny IPv4/IPv6/CIDR whitelist.
11. Unauthorized requests receive HTTP 403 before reaching Jellyfin.
12. Forwarded client-IP headers are not trusted.
13. CDN and upstream proxy support are excluded.
14. No LAN routing, router port forwarding, or full-tunnel home VPN is used.
15. Jellyfin's default TCP port is 8096.

## Runtime and deployment

16. Production target is Ubuntu 26.04 LTS x64.
17. Deployment uses Docker Engine and Docker Compose.
18. VPS runtime comprises Caddy, WireGuard, and Go admin containers.
19. Caddy and WireGuard share the WireGuard container's network namespace.
20. The WireGuard service namespace publishes required HTTP/HTTPS ports.
21. Containers use `restart: unless-stopped`.
22. Container images are pinned and tested; immutable digests are preferred
    where practical.
23. Caddy administration is available only through a private Unix socket.
24. Admin has no Docker socket access.
25. Static site content persists separately from releasable application files.
26. Windows uses the official native WireGuard client.
27. Windows initiates the tunnel and uses persistent keepalive.
28. Normal Windows Internet traffic remains outside the tunnel.
29. The Windows configuration is retained securely and downloadable more than
    once after admin authentication.
30. Windows Firewall guidance restricts access to the VPS WireGuard address.

## Security and applications

31. Passwords are strongly hashed; initial password entry is hidden in the CLI.
32. Sessions and cookies are secure, with login, logout, and expiry behaviour.
33. State-changing admin operations use CSRF protection.
34. Login attempts receive basic protection.
35. `proxyctl reset-password` performs a local reset and invalidates sessions.
36. Sensitive config and WireGuard keys have restricted filesystem permissions.
37. Configuration writes are atomic and whitelist updates transactional.
38. Invalid or failed changes preserve the last valid configuration and do not
    fail open.
39. WireGuard downloads are authenticated and non-cacheable.
40. Both applications use Go in one module; admin uses server-rendered HTML,
    CSS, and minimal JavaScript.
41. `proxyctl` is a standalone native Linux x64 executable for install, update,
    password reset, rollback, and necessary deployment operations.

## Release and workflow decisions

The release process uses `main` for stable code and `dev` for integration,
short-lived feature/fix branches, PRs into `dev`, and tested promotion into
`main`. No GitHub Actions or hosted CI. Release packages bundle all required
container images so installation does not pull application images from a
registry. Updates retain the active and one previous good release, preserve
persistent data, roll back failed health checks where possible, and never
globally prune Docker images. Normal Docker APT updates are not held.

Excluded features are listed in `AGENTS.md` and the supplied implementation
brief. The 41 numbered points above are a transcription/condensation of
explicit requirements in that brief, not a substitute for any separate source
decision list if one is later supplied.

## Implementation details (not additional product decisions)

- M1 local hostnames use the reserved `.test` namespace.
- Local HTTPS uses Caddy's internal CA; integration requests skip verification
  because the CA is not installed into the Windows trust store.
- The admin hostname returns HTTP 503 during M1 until the admin milestone.
- M1 publishes test ports only on loopback and uses an isolated, uniquely
  named Compose project.
