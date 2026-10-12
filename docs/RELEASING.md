# Releasing

The M7 package builder is implemented. The production installer, updater, and
complete M10 release gate are still roadmap work.

## Versioning and package

Use semantic versions; the first release is `1.0.0`. Build a package with
`./build.ps1 package -Version 1.0.0-dev` during development. The target release bundle
contains a standalone Linux x64 `proxyctl`, versioned manifest, deployment
templates, and every required Docker image as an archive. A clean installation
must not pull application images from a registry. Package compatibility and
image identities must be validated before install/update.

## Required release gates

- All Go unit and integration tests pass.
- Caddy host routing and HTTPS tests pass.
- Whitelist, auth, session, CSRF, and admin update tests pass.
- WireGuard and mocked Jellyfin tunnel tests pass.
- Package contents are validated and images load into a clean Docker daemon.
- Fresh installation, data preservation, failure rollback, restart, and
  retention tests pass.
- No unrelated Docker resources are removed or changed.
- Host-specific preflight checks exist; local simulation is not represented as
  proof of public TLS or VPS firewall behaviour.

## Branch and publication process

Use short-lived feature/fix PRs into `dev`. Run `build.ps1 release` before
promotion, then merge tested `dev` into `main`, verify the release commit, and
tag it. Do not create temporary release branches and do not add hosted CI or
GitHub Actions. Publish artifacts only when repository permissions allow and
only after every mandatory gate passes.

## Rollback and retention

Updates preserve persistent data and retain the active and one previous
known-good application release. Roll back when post-update readiness fails.
Remove only older application-owned release artifacts after successful
verification. Never globally prune Docker images or alter unrelated Docker
resources. Host Docker Engine and Compose receive normal APT updates.
