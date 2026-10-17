FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/wgcontrol ./cmd/wgcontrol
COPY internal/wireguard ./internal/wireguard
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/wgcontrol ./cmd/wgcontrol

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache bash=5.3.9-r1 iproute2=7.0.0-r0 iptables=1.8.13-r0 wireguard-tools=1.0.20260223-r0
COPY --from=build /out/wgcontrol /usr/local/bin/wgcontrol
COPY deploy/wireguard/entrypoint.sh /usr/local/bin/wireguard-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/wireguard-entrypoint && chmod 0755 /usr/local/bin/wireguard-entrypoint
EXPOSE 51820/udp
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=6 CMD sh -c 'wg show "${WIREGUARD_INTERFACE:-wg0}" >/dev/null 2>&1 && ip link show "${WIREGUARD_INTERFACE:-wg0}" >/dev/null 2>&1'
ENTRYPOINT ["/usr/local/bin/wireguard-entrypoint"]
