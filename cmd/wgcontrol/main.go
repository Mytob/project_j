package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mytob/project_j/internal/wireguard"
)

func main() {
	serverConfig := flag.String("server-config", "/etc/wireguard/server.conf", "persistent WireGuard server configuration")
	clientConfig := flag.String("client-config", "/var/lib/wireguard-client/windows.conf", "one-time Windows client configuration")
	socket := flag.String("socket", "/run/wireguard-control/control.sock", "private WireGuard control socket")
	iface := flag.String("interface", "wg0", "WireGuard interface name")
	group := flag.Int("admin-group", 65532, "administrator container group permitted to use the control socket")
	flag.Parse()

	controller, err := wireguard.NewPeerController(*serverConfig, *clientConfig, *iface, "wg")
	if err != nil {
		slog.Error("configure WireGuard peer controller", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := wireguard.ListenControl(ctx, *socket, controller, *group); err != nil {
		slog.Error("WireGuard control service stopped", "error", err)
		os.Exit(1)
	}
}
