# Project instructions

## Product scope

Preserve the Jellyfin Proxy 1.0 requirements in `docs/DECISIONS.md` and
`docs/ROADMAP.md`, and implement the specifically authorized Jellyfin Proxy
v1.1 TOTP administrator-authentication requirements supplied by the user.
Keep the v1.1 scope frozen to those TOTP requirements. Implement the
specifically authorized v1.2 admin redesign and host/proxy statistics scope
recorded in `docs/V1.2.md`, without expanding the approved scope. Do not add
other media services, users, registration, external proxy/CDN support, LAN
routing, full-tunnel VPN, databases, microservices, Kubernetes, hosted CI,
release signing, encrypted backups, or unrelated operations features.

## Architecture rules

- Keep one Go module and separate executable entry points under `cmd/`.
- Put reusable behaviour in focused `internal/` packages. Keep dependencies
  moving inward toward domain code and the Go standard library where practical.
- Keep the administrator server-rendered, with no frontend framework or
  JavaScript runtime dependency.
- Keep persistent deployment data separate from replaceable release files.
- Do not expose Caddy's administration endpoint or mount the Docker socket in
  the admin container.
- Preserve persistent config, credentials, whitelist entries, WireGuard keys,
  and website files during updates.
- Fail closed when access-control configuration cannot be validated or applied.
- Keep monitoring private: no published collector port, no Docker socket, authenticated admin-only statistics endpoints, bounded SSE subscribers, and bounded 90-day file history.
- Run the host metrics collector unprivileged with read-only host metric mounts; do not add host services or host network/PID namespace access.
- Count proxy traffic in Caddy while bytes are in flight; do not buffer media streams or infer transfer rates only from completed requests.

## Tests and milestone gates

- Add deterministic tests for each behaviour and keep tests isolated from live
  services and unrelated Docker resources.
- Run focused Go tests and relevant integration tests while developing.
- Do not start the next roadmap milestone until the current milestone's gate
  passes. Report an unavailable mandatory environment capability as a blocker;
  never silently skip the gate.
- `build.ps1 test` is the local validation entry point. The eventual release
  gate is `build.ps1 release`; it must report every mandatory check.
- v1.2 changes must pass every mandatory local check in the handoff, including real browser, collector/container, streaming, history/SSE, and package upgrade/rollback coverage, before pushing or opening a PR. Do not report unexecuted checks as passed.
- Record only commands actually run and observed results in `docs/ROADMAP.md`
  and `docs/TESTING.md`.

## Source control

- Use `main` for stable releases and `dev` for integration.
- Use short-lived `feature/*` and `fix/*` branches and pull requests into `dev`.
- Promote tested `dev` to `main` for releases. Do not add GitHub Actions.
- Keep commits focused and do not commit credentials, private keys, deployment
  state, or generated release artifacts.

## Documentation and definition of done

- Keep the roadmap current with each milestone's status, deliverables, tests,
  evidence, issues, and any commit or pull request.
- Keep architecture, security boundaries, operator instructions, and test
  claims aligned with implemented behaviour.
- A milestone is complete only when its required behaviour and automated tests
  pass. A file's presence is not completion evidence.
- Preserve existing persistent data and unrelated Docker resources.
- Prefer the smallest maintainable implementation that meets the frozen scope.
