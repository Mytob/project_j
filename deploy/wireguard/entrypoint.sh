#!/bin/sh
set -eu

config="${WIREGUARD_CONFIG:-/etc/wireguard/wg0.conf}"
wg-quick up "$config"
down() {
	wg-quick down "$config" || true
}
trap down EXIT INT TERM

while :; do
	sleep 3600 &
	wait $!
done
