package deployment

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DetectHostFacts reads os-release and the architecture/effective uid from the
// host rather than inferring them from the package or Docker image.
func DetectHostFacts(ctx context.Context, runner CommandRunner) (HostFacts, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return HostFacts{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	values := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return HostFacts{}, err
	}
	arch, err := runner.Run(ctx, "uname", "-m")
	if err != nil {
		return HostFacts{}, fmt.Errorf("read host architecture: %w", err)
	}
	uid, err := runner.Run(ctx, "id", "-u")
	if err != nil {
		return HostFacts{}, fmt.Errorf("read effective user id: %w", err)
	}
	effectiveUID, err := strconv.Atoi(strings.TrimSpace(uid))
	if err != nil {
		return HostFacts{}, fmt.Errorf("parse effective user id: %w", err)
	}
	codename := values["UBUNTU_CODENAME"]
	if codename == "" {
		codename = values["VERSION_CODENAME"]
	}
	return HostFacts{OSID: values["ID"], VersionID: values["VERSION_ID"], Codename: codename, Arch: strings.TrimSpace(arch), EffectiveUID: effectiveUID}, nil
}
