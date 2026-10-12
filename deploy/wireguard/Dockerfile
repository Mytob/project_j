FROM alpine:3.22
RUN apk add --no-cache bash iproute2 wireguard-tools
COPY deploy/wireguard/entrypoint.sh /usr/local/bin/wireguard-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/wireguard-entrypoint && chmod 0755 /usr/local/bin/wireguard-entrypoint
EXPOSE 51820/udp
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=6 CMD sh -c 'wg show "${WIREGUARD_INTERFACE:-wg0}" >/dev/null 2>&1 && ip link show "${WIREGUARD_INTERFACE:-wg0}" >/dev/null 2>&1'
ENTRYPOINT ["/usr/local/bin/wireguard-entrypoint"]
