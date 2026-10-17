FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/securityd ./cmd/securityd
COPY internal/security ./internal/security
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/securityd ./cmd/securityd

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
ARG FAIL2BAN_VERSION=1.1.0-8
ARG SYSTEMD_VERSION=257.13-1~deb13u1
ARG NFTABLES_VERSION=1.1.3-1
ARG PYTHON_SYSTEMD_VERSION=235-1+b6
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends fail2ban=${FAIL2BAN_VERSION} systemd=${SYSTEMD_VERSION} nftables=${NFTABLES_VERSION} python3-systemd=${PYTHON_SYSTEMD_VERSION} ca-certificates && rm -rf /var/lib/apt/lists/*
COPY deploy/fail2ban/jail.local /etc/fail2ban/jail.local
COPY deploy/fail2ban/filter.d/jp-manual.conf /etc/fail2ban/filter.d/jp-manual.conf
COPY deploy/fail2ban/action.d/jp-noop.conf /etc/fail2ban/action.d/jp-noop.conf
COPY deploy/fail2ban/action.d/nftables-common.local /etc/fail2ban/action.d/nftables-common.local
COPY --from=build /out/securityd /usr/local/bin/securityd
RUN install -d -m 0700 /var/lib/jellyfin-proxy/security /var/lib/fail2ban && install -o root -g root -m 0600 /dev/null /var/lib/fail2ban/admin-events-disabled.log
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TMPDIR=/tmp
ENTRYPOINT ["/usr/local/bin/securityd"]
