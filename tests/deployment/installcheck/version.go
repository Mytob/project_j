package main

import (
	"fmt"
	"strconv"
	"strings"
)

// bumpPatchVersion gives package integration updates deterministic versions
// after the package under test while preserving its prerelease/build suffix.
func bumpPatchVersion(version string, increment int) (string, error) {
	if increment < 1 {
		return "", fmt.Errorf("patch increment must be positive")
	}
	coreAndPrerelease, build, hasBuild := strings.Cut(version, "+")
	core, prerelease, hasPrerelease := strings.Cut(coreAndPrerelease, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("version %q does not have three numeric components", version)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil || patch < 0 || patch > int(^uint(0)>>1)-increment {
		return "", fmt.Errorf("version %q has an invalid patch component", version)
	}
	parts[2] = strconv.Itoa(patch + increment)
	result := strings.Join(parts, ".")
	if hasPrerelease {
		result += "-" + prerelease
	}
	if hasBuild {
		result += "+" + build
	}
	return result, nil
}
