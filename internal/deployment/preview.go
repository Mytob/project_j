package deployment

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/release"
)

type UpdatePreview struct {
	CurrentVersion   string
	CurrentBuildID   string
	CandidateVersion string
	CandidateBuildID string
	TargetOS         string
	Architecture     string
	DatabaseSchemaMin int
	DatabaseSchemaMax int
}

// PreviewUpdatePackage fully verifies the user-supplied package and reports
// the compatibility facts that the dashboard must show before it can queue an
// update. Update repeats these checks immediately before changing the host.
func PreviewUpdatePackage(ctx context.Context, installRoot, packagePath, checksum string) (UpdatePreview, error) {
	if checksum == "" {
		return UpdatePreview{}, errors.New("an independently supplied package SHA-256 is required")
	}
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if !filepath.IsAbs(installRoot) {
		return UpdatePreview{}, errors.New("installation root must be absolute")
	}
	if err := validateUpdateRoot(installRoot); err != nil {
		return UpdatePreview{}, err
	}
	current, err := readCurrentRelease(installRoot)
	if err != nil {
		return UpdatePreview{}, err
	}
	candidate, err := release.ValidatePackage(packagePath, checksum)
	if err != nil {
		return UpdatePreview{}, fmt.Errorf("release package validation failed: %w", err)
	}
	if err := validateProxyctlMinimum(candidate); err != nil {
		return UpdatePreview{}, err
	}
	if err := validatePackagePortAndVersion(candidate, defaultWireGuardPort); err != nil {
		return UpdatePreview{}, err
	}
	comparison, err := release.CompareVersions(candidate.Version, current.Version)
	if err != nil {
		return UpdatePreview{}, err
	}
	if comparison <= 0 {
		return UpdatePreview{}, fmt.Errorf("candidate %s must be newer than active release %s", candidate.Version, current.Version)
	}
	if !supportsUpgradeFrom(candidate, current.Version) {
		return UpdatePreview{}, fmt.Errorf("candidate %s does not support updating from %s", candidate.Version, current.Version)
	}
	databaseSchema, err := monitoring.HistoryDatabaseSchema(filepath.Join(installRoot, "data", "statistics", "statistics.db"))
	if err != nil {
		return UpdatePreview{}, fmt.Errorf("inspect current statistics schema: %w", err)
	}
	if databaseSchema < current.DatabaseSchemaMinimum || databaseSchema > current.DatabaseSchemaMaximum || databaseSchema < candidate.DatabaseSchemaMinimum || databaseSchema > candidate.DatabaseSchemaMaximum {
		return UpdatePreview{}, fmt.Errorf("database schema %d is incompatible with active/candidate release requirements", databaseSchema)
	}
	return UpdatePreview{CurrentVersion: current.Version, CurrentBuildID: current.BuildID, CandidateVersion: candidate.Version, CandidateBuildID: candidate.BuildID, TargetOS: candidate.TargetOS, Architecture: candidate.Architecture, DatabaseSchemaMin: candidate.DatabaseSchemaMinimum, DatabaseSchemaMax: candidate.DatabaseSchemaMaximum}, nil
}
