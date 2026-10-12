# Releasing

The M7 package builder, M8 first-install flow, M9 update/recovery commands,
and M10 local release gate are implemented. A passing local gate records
production-host checks as blocked until they are run on the actual VPS and
Windows client.

## Versioning and package

Use semantic versions; the first release is `1.0.0`. Build a package with
`./build.ps1 package -Version 1.0.0-dev` during development. The target release
bundle contains standalone Linux x64 `proxyctl` and admin executables, a
versioned manifest, deployment templates, and every required Docker image as
an archive. A clean installation or update must not pull application images
from a registry. Package compatibility and image identities must be validated
before install/update.

Run `./build.ps1 release -Version 1.0.0-dev` for the complete locally
automated gate. The command writes a JSON report to
`dist/release-validation-<Version>.json`, including individual gate statuses
and any host-specific blockers. A passing local gate is not a publish-ready
release while production-host checks remain blocked.

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

The M8–M9 package gate runs the actual installer and updater against an
isolated Docker-in-Docker daemon with image-registry access disabled. It
verifies fresh install, IPv4/IPv6 namespace ingress filters, host INPUT
preservation, update data preservation, failure recovery, active/previous
release retention, password reset, and failure cleanup while an unrelated
container remains running. This is not an Ubuntu VPS, public TLS, or provider
firewall test; the operator must allow TCP 80/443 and the configured UDP port
at the VPS provider.

## Branch and publication process

Use short-lived feature/fix PRs into `dev`. Run `build.ps1 release` before
promotion. Promote tested `dev` to `main`, verify the release commit, and tag
it only after every mandatory gate passes, including the production-host checks
recorded by the release report. Do not create temporary release branches and
do not add hosted CI or GitHub Actions. Publish artifacts only when repository
permissions allow and only after every mandatory gate passes.

## Rollback and retention

Updates preserve persistent data and retain the active and one previous
known-good application release. Roll back when post-update readiness fails.
Remove only older application-owned release artifacts after successful
verification. Never globally prune Docker images or alter unrelated Docker
resources. Host Docker Engine and Compose receive normal APT updates.
