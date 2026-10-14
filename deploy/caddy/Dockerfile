FROM caddy:2.10.2-builder-alpine@sha256:4cff3ae272ea05842adb4546e35961e4947aeea65f80fa1eb62a35b960e84971 AS build
WORKDIR /src
COPY go.mod go.sum caddyplugin.go ./
COPY internal/caddytelemetry ./internal/caddytelemetry
RUN xcaddy build v2.10.2 --with github.com/Mytob/project_j=.

FROM caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d
COPY --from=build /src/caddy /usr/bin/caddy
