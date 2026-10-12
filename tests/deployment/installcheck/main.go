// installcheck exercises the real installer against a disposable Docker-in-
// Docker daemon after the release archive has been loaded without networking.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mytob/project_j/internal/deployment"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "installer integration:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: installcheck <release-package.tar.gz>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runner := deployment.ExecRunner{}
	packagePath, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	options := deployment.InstallOptions{
		PackagePath: packagePath, InstallRoot: "/opt/jellyfin-proxy-installcheck", Domain: "installcheck.example.invalid",
		Password: "correct horse battery staple", WireGuardPort: 51820,
		Host:   deployment.HostFacts{OSID: "ubuntu", VersionID: "26.04", Codename: "resolute", Arch: "x86_64", EffectiveUID: 0},
		Runner: runner, WaitInterval: time.Second, WaitAttempts: 60,
		DNSLookup:  func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil },
		HTTPSCheck: func(context.Context, string) error { return nil },
	}
	hostInputBefore, err := runner.Run(ctx, "iptables", "-S", "INPUT")
	if err != nil {
		return fmt.Errorf("capture isolated host firewall before install: %w", err)
	}
	manifest, err := deployment.Install(ctx, options)
	if err != nil {
		return fmt.Errorf("fresh install failed: %w", err)
	}
	if manifest.Version == "" {
		return errors.New("installer returned an empty release version")
	}
	// Published Docker ports bypass many host INPUT policies after DNAT. Confirm
	// the production WireGuard namespace installs its own narrow ingress filter.
	for _, family := range []struct{ firewall, chain string }{
		{firewall: "iptables", chain: "JELLYFIN_PROXY_INPUT"},
		{firewall: "ip6tables", chain: "JELLYFIN_PROXY_INPUT6"},
	} {
		rules, err := runner.Run(ctx, "docker", "compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(options.InstallRoot, "compose.yaml"), "--env-file", filepath.Join(options.InstallRoot, ".env"), "exec", "--no-TTY", "wireguard", family.firewall, "-S", family.chain)
		if err != nil {
			return fmt.Errorf("inspect deployment %s firewall: %w", family.firewall, err)
		}
		fmt.Printf("Deployment %s ingress firewall rules:\n%s\n", family.firewall, rules)
		for _, expected := range []string{
			"--dport 80 -j ACCEPT",
			"--dport 443 -j ACCEPT",
			"--dport 51820 -j ACCEPT",
			"-j DROP",
		} {
			if !strings.Contains(rules, expected) {
				return fmt.Errorf("deployment %s firewall is missing %q", family.firewall, expected)
			}
		}
	}
	hostInputAfter, err := runner.Run(ctx, "iptables", "-S", "INPUT")
	if err != nil || hostInputAfter != hostInputBefore {
		return fmt.Errorf("installer changed the isolated host INPUT firewall: before=%q after=%q err=%v", hostInputBefore, hostInputAfter, err)
	}
	if err := cleanupDeployment(runner, options.InstallRoot); err != nil {
		return err
	}

	// Reserve a published port to force Compose startup failure after preflight.
	// The installer must remove its own partial deployment while leaving this
	// unrelated container alone.
	conflictName := "jellyfin-proxy-installcheck-port-conflict"
	if _, err := runner.Run(ctx, "docker", "run", "--detach", "--name", conflictName, "--publish", "80:80", "alpine:3.22", "sleep", "240"); err != nil {
		return fmt.Errorf("create scoped port-conflict fixture: %w", err)
	}
	defer func() { _, _ = runner.Run(context.Background(), "docker", "rm", "--force", conflictName) }()
	failureOptions := options
	failureOptions.InstallRoot = "/opt/jellyfin-proxy-installcheck-failure"
	if _, err := deployment.Install(ctx, failureOptions); err == nil {
		return errors.New("installer unexpectedly succeeded while public port 80 was already allocated")
	}
	if _, err := os.Lstat(failureOptions.InstallRoot); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed installation left partial files at %s", failureOptions.InstallRoot)
	}
	state, err := runner.Run(ctx, "docker", "inspect", "--format", "{{.State.Running}}", conflictName)
	if err != nil || strings.TrimSpace(state) != "true" {
		return errors.New("failed installation changed or removed the unrelated port-conflict container")
	}
	fmt.Printf("M8 package install and failure rollback passed for release %s.\n", manifest.Version)
	return nil
}

func cleanupDeployment(runner deployment.CommandRunner, root string) error {
	_, err := runner.Run(context.Background(), "docker", "compose", "--project-name", "jellyfin-proxy", "--file", filepath.Join(root, "compose.yaml"), "--env-file", filepath.Join(root, ".env"), "down", "--remove-orphans", "--volumes")
	if err != nil {
		return fmt.Errorf("stop successful installer fixture: %w", err)
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove installer fixture: %w", err)
	}
	return nil
}
