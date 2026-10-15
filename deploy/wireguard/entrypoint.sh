#!/bin/sh
set -eu

config="${WIREGUARD_CONFIG:-/etc/wireguard/wg0.conf}"
interface="${WIREGUARD_INTERFACE:-wg0}"
health_dir="${WIREGUARD_HEALTH_DIR:-/run/wireguard-health}"
client_config="${WIREGUARD_CLIENT_CONFIG:-/var/lib/wireguard-client/windows.conf}"
control_socket="${WIREGUARD_CONTROL_SOCKET:-/run/wireguard-control/control.sock}"
admin_group="${WIREGUARD_ADMIN_GROUP:-65532}"

# Docker-published ports are DNATed before the host firewall's normal INPUT
# rules. Filter ingress in this service's own network namespace instead, so
# only Caddy's public ports and WireGuard's container port are reachable. This
# leaves host SSH and unrelated firewall/container rules untouched.
if [ "$interface" != "windows" ]; then
	setup_ingress_filter() {
		firewall="$1"
		filter="$2"
		if ! "$firewall" -w -S "$filter" >/dev/null 2>&1; then
			"$firewall" -w -N "$filter"
		fi
		"$firewall" -w -F "$filter"
		"$firewall" -w -A "$filter" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
		"$firewall" -w -A "$filter" -i lo -j ACCEPT
		if [ "$firewall" = iptables ]; then
			"$firewall" -w -A "$filter" -i "$interface" -s 10.66.66.2/32 -j ACCEPT
		fi
		"$firewall" -w -A "$filter" -p tcp --dport 80 -j ACCEPT
		"$firewall" -w -A "$filter" -p tcp --dport 443 -j ACCEPT
		"$firewall" -w -A "$filter" -p udp --dport 51820 -j ACCEPT
		"$firewall" -w -A "$filter" -j DROP
		if ! "$firewall" -w -C INPUT -j "$filter" >/dev/null 2>&1; then
			"$firewall" -w -I INPUT 1 -j "$filter"
		fi
	}
	setup_ingress_filter iptables JELLYFIN_PROXY_INPUT
	setup_ingress_filter ip6tables JELLYFIN_PROXY_INPUT6
fi

wg-quick up "$config"
/usr/local/bin/wgcontrol --server-config "$config" --client-config "$client_config" --socket "$control_socket" --interface "$interface" --admin-group "$admin_group" &
control_pid=$!
mkdir -p "$health_dir"
update_health() {
	if wg show "$interface" >/dev/null 2>&1 && ip link show "$interface" >/dev/null 2>&1; then
		temporary="$health_dir/current.tmp"
		date +%s > "$temporary"
		mv "$temporary" "$health_dir/current"
	else
		rm -f "$health_dir/current" "$health_dir/current.tmp"
	fi
}
down() {
	kill "$control_pid" 2>/dev/null || true
	wait "$control_pid" 2>/dev/null || true
	wg-quick down "$config" || true
	update_health
}
trap down EXIT INT TERM

while :; do
	if ! kill -0 "$control_pid" 2>/dev/null; then
		echo "WireGuard control service stopped unexpectedly" >&2
		exit 1
	fi
	update_health
	sleep 5 &
	wait $!
done
