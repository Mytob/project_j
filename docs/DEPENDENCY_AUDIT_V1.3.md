# v1.3 dependency audit

Audit date: 2026-10-15. Exact versions and image digests are committed in the
lockfiles and Dockerfiles; this record captures the observed checks for the
v1.3 implementation.

## Frontend

`internal/admin/frontend/package.json` pins React and React DOM 19.3.1,
TypeScript 7.0.2, Vite 8.3.4, Vitest 5.0.5, `@vitejs/plugin-react` 6.1.2,
and React type packages 19.3.0. `package-lock.json` locks the complete tree.
The exact latest npm registry versions observed on 2026-10-15 matched those
pins. The build and browser-test toolchain uses Node 24.22.0 on Alpine 3.24
with npm 12.2.0 pinned by the Docker build/test commands. The Node image
bundled npm 11.19.1; `npm view npm version` returned 12.2.0, whose declared
engine range includes Node 24.22.0. The Node release was published on
2026-10-14 as an LTS update ([official release notes](https://nodejs.org/en/blog/release/v24.22.0)).
Node and npm are not part of the production runtime image.

`npm audit` was run for the frontend and for the separately locked browser
integration package. Both reported zero vulnerabilities.

## Go and container images

- The module declares Go 1.26.0 and Caddy 2.11.7. The Go build/test container
  uses Go 1.27.2 on Alpine 3.24; the Caddy builder and runtime images are both
  pinned to 2.11.7. Go 1.27.2's release is recorded in the [official Go
  release history](https://go.dev/doc/devel/release); Caddy 2.11.7 is recorded
  in the [official Caddy releases](https://github.com/caddyserver/caddy/releases).
- The pinned Caddy builder image contains xcaddy 0.4.7, verified by running
  `xcaddy version` in the image. This matches the latest version in the
  [official xcaddy releases](https://github.com/caddyserver/xcaddy/releases).
- The browser suite pins `@playwright/test` 1.64.1, the latest official release
  observed on 2026-10-15 ([Playwright v1.64.1](https://github.com/microsoft/playwright/releases/tag/v1.64.1)).
  Its browser image is pinned to
  `mcr.microsoft.com/playwright:v1.64.1-noble@sha256:7852dc5a7d72f5fe458a597d690f6c42fbc8e9e26ddfa95f8e6ef552558d9bbf`.
  It is test-only. The browser smoke suite covers Chromium, Firefox, and WebKit.
- Node 24.22.0 Alpine 3.24 image digest:
  `sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f`.
- Go 1.27.2 Alpine 3.24 image digest:
  `sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d`.
- Alpine 3.24.2 image digest:
  `sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`.
- Caddy 2.11.7 Alpine runtime image digest:
  `sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f`.
- Caddy 2.11.7 builder image digest:
  `sha256:d6161a2c82fd58b3205048958fb6246d0c5d892beee8a47e90944610c4efd100`.
- WireGuard and host-metrics Alpine images pin Alpine 3.24.2 packages to
  `bash=5.3.9-r1`, `iproute2=7.0.0-r0`, `iptables=1.8.13-r0`, and
  `wireguard-tools=1.0.20260223-r0` as applicable.

The package gate successfully built and loaded its five images in an isolated
Docker-in-Docker daemon without registry access, then passed install, update,
and rollback checks. This verifies the actual pinned inputs resolve and the
resulting bundle can be consumed offline; it is not a substitute for a full
third-party container image vulnerability database scan.

## Vulnerability scan results and limits

- The pinned `govulncheck` v1.9.0 scan ran with Go 1.27.2. It reported no
  vulnerable symbols or vulnerabilities in code reachable by this module.
- The scanner also reported GO-2026-5932 as a module-only, no-fix advisory for
  `golang.org/x/crypto/openpgp` in `golang.org/x/crypto v0.58.0`. The main
  module does not import that package (`go mod why
  golang.org/x/crypto/openpgp` confirms no dependency path); the module is
  retained for other packages. Recheck this advisory when upstream publishes
  a fix or the dependency graph changes.
- Docker Scout v1.26.0 image scanning was considered but not run. Automatic
  approval review rejected the requested operation because it would transmit
  SBOM/package metadata from locally built private images to an external
  service. No attempt was made to bypass that review. A local scanner with a
  suitable current database can be used if available.

## Sources

Version references above are pinned in `go.mod`, `go.sum`, the frontend npm
lockfiles, and the production Dockerfiles; the Playwright test image is pinned
separately by digest. Upstream version context:
[Node.js release notes](https://nodejs.org/en/blog/release/v24.22.0),
[Go release history](https://go.dev/doc/devel/release), [Caddy releases](https://github.com/caddyserver/caddy/releases),
and [Alpine downloads](https://www.alpinelinux.org/downloads/).
