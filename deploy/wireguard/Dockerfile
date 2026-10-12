FROM alpine:3.22
RUN apk add --no-cache bash iproute2 wireguard-tools
COPY deploy/wireguard/entrypoint.sh /usr/local/bin/wireguard-entrypoint
RUN chmod 0755 /usr/local/bin/wireguard-entrypoint
EXPOSE 51820/udp
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=6 CMD wg show wg0 >/dev/null 2>&1 && ip link show wg0 >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/wireguard-entrypoint"]
