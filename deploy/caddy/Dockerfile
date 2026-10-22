FROM caddy:2.11.7-builder-alpine@sha256:d6161a2c82fd58b3205048958fb6246d0c5d892beee8a47e90944610c4efd100 AS build
WORKDIR /src
COPY go.mod go.sum caddyplugin.go ./
COPY internal/caddytelemetry ./internal/caddytelemetry
RUN xcaddy build v2.11.7 --with github.com/Mytob/project_j=.

FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
COPY --from=build /src/caddy /usr/bin/caddy
LABEL jellyfin.proxy.component-version="2.11.7"
