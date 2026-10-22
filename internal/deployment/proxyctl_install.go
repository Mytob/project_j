package deployment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	defaultProxyctlDir      = "/usr/local/sbin"
	defaultProxyctlStateDir = "/usr/local/lib/jellyfin-proxy"
	proxyctlJournalName     = ".proxyctl-replacement.json"
	proxyctlMarkerName      = "proxyctl-managed.json"
	proxyctlPreviousName    = "proxyctl.previous"
)

type proxyctlReplacement struct {
	Version       int    `json:"version"`
	Owner         string `json:"owner"`
	Stage         string `json:"stage"`
	VersionString string `json:"version_string"`
	TargetSHA256  string `json:"target_sha256"`
}

type proxyctlManaged struct {
	Version  int    `json:"version"`
	Owner    string `json:"owner"`
	Current  string `json:"current_sha256"`
	Previous string `json:"previous_sha256,omitempty"`
	Release  string `json:"release"`
}

// InstallPersistentProxyctl atomically installs the utility from a verified
// retained release. It refuses to replace an executable without this product's
// ownership marker and keeps the prior executable in its private state folder.
func InstallPersistentProxyctl(installRoot, releaseVersion, binaryDirectory, stateDirectory string) error {
	if installRoot == "" {
		installRoot = DefaultInstallRoot
	}
	if releaseVersion == "" || filepath.Base(releaseVersion) != releaseVersion {
		return errors.New("proxyctl release version is invalid")
	}
	if binaryDirectory == "" {
		binaryDirectory = defaultProxyctlDir
	}
	if stateDirectory == "" {
		stateDirectory = defaultProxyctlStateDir
	}
	if !filepath.IsAbs(binaryDirectory) || !filepath.IsAbs(stateDirectory) {
		return errors.New("proxyctl install and state directories must be absolute")
	}
	source := filepath.Join(installRoot, "releases", releaseVersion, "bin", "proxyctl-linux-amd64")
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 || sourceInfo.Size() == 0 {
		return errors.New("verified release proxyctl executable is missing or unsafe")
	}
	if err := os.MkdirAll(binaryDirectory, 0o755); err != nil {
		return fmt.Errorf("create proxyctl executable directory: %w", err)
	}
	if err := os.MkdirAll(stateDirectory, 0o750); err != nil {
		return fmt.Errorf("create proxyctl state directory: %w", err)
	}
	stateInfo, err := os.Lstat(stateDirectory)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("proxyctl state path is not a real directory")
	}
	if err := os.Chmod(stateDirectory, 0o750); err != nil {
		return fmt.Errorf("secure proxyctl state directory: %w", err)
	}
	destination := filepath.Join(binaryDirectory, "proxyctl")
	markerPath := filepath.Join(stateDirectory, proxyctlMarkerName)
	journalPath := filepath.Join(stateDirectory, proxyctlJournalName)
	previousPath := filepath.Join(stateDirectory, proxyctlPreviousName)
	if _, err := os.Lstat(journalPath); err == nil {
		if err := RecoverPersistentProxyctl(binaryDirectory, stateDirectory); err != nil {
			return fmt.Errorf("recover prior proxyctl replacement: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	currentInfo, err := os.Lstat(destination)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect persistent proxyctl: %w", err)
	}
	var previousHash string
	if currentInfo != nil {
		if !currentInfo.Mode().IsRegular() || currentInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("persistent proxyctl destination is not a regular executable")
		}
		marker, markerErr := readProxyctlMarker(markerPath)
		if markerErr != nil {
			return errors.New("refusing to replace an unowned /usr/local/sbin/proxyctl executable")
		}
		currentHash, hashErr := sha256File(destination)
		if hashErr != nil || currentHash != marker.Current {
			return errors.New("managed proxyctl does not match its recorded checksum; preserve it and run proxyctl doctor")
		}
		if err := copyAtomic(destination, previousPath, 0o750); err != nil {
			return fmt.Errorf("retain previous proxyctl executable: %w", err)
		}
		previousHash = currentHash
	}
	targetHash, err := sha256File(source)
	if err != nil {
		return fmt.Errorf("hash replacement proxyctl: %w", err)
	}
	journal := proxyctlReplacement{Version: 1, Owner: "jellyfin-proxy", Stage: "prepared", VersionString: releaseVersion, TargetSHA256: targetHash}
	if err := writeJSONAtomic(journalPath, journal, 0o600); err != nil {
		return fmt.Errorf("write proxyctl recovery journal: %w", err)
	}
	if err := copyAtomic(source, destination, 0o755); err != nil {
		return fmt.Errorf("atomically install proxyctl: %w", err)
	}
	installedHash, err := sha256File(destination)
	if err != nil || installedHash != targetHash {
		return errors.New("installed proxyctl failed checksum verification")
	}
	managed := proxyctlManaged{Version: 1, Owner: "jellyfin-proxy", Current: targetHash, Previous: previousHash, Release: releaseVersion}
	if err := writeJSONAtomic(markerPath, managed, 0o600); err != nil {
		return fmt.Errorf("record managed proxyctl checksum: %w", err)
	}
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear proxyctl replacement journal: %w", err)
	}
	return syncDirectory(stateDirectory)
}

// RecoverPersistentProxyctl completes an interrupted atomic replacement when
// the new file is already present, or leaves the previous intact executable in
// place and clears the journal when the replacement had not committed.
func RecoverPersistentProxyctl(binaryDirectory, stateDirectory string) error {
	if binaryDirectory == "" {
		binaryDirectory = defaultProxyctlDir
	}
	if stateDirectory == "" {
		stateDirectory = defaultProxyctlStateDir
	}
	path := filepath.Join(stateDirectory, proxyctlJournalName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		return errors.New("proxyctl replacement journal is missing or unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var journal proxyctlReplacement
	if err := json.Unmarshal(data, &journal); err != nil || journal.Version != 1 || journal.Owner != "jellyfin-proxy" || journal.Stage != "prepared" || journal.TargetSHA256 == "" || len(journal.TargetSHA256) != 64 || journal.VersionString == "" || filepath.Base(journal.VersionString) != journal.VersionString {
		return errors.New("proxyctl replacement journal is invalid; manual recovery is required")
	}
	destination := filepath.Join(binaryDirectory, "proxyctl")
	destinationInfo, destinationErr := os.Lstat(destination)
	if destinationErr == nil && (!destinationInfo.Mode().IsRegular() || destinationInfo.Mode()&os.ModeSymlink != 0) {
		return errors.New("proxyctl replacement destination is unsafe")
	}
	if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
		return destinationErr
	}
	if hash, err := sha256File(destination); err == nil && hash == journal.TargetSHA256 {
		managed := proxyctlManaged{Version: 1, Owner: "jellyfin-proxy", Current: hash, Release: journal.VersionString}
		if old, oldErr := readProxyctlMarker(filepath.Join(stateDirectory, proxyctlMarkerName)); oldErr == nil {
			managed.Previous = old.Current
		} else if previousHash, hashErr := sha256File(filepath.Join(stateDirectory, proxyctlPreviousName)); hashErr == nil {
			managed.Previous = previousHash
		}
		if err := writeJSONAtomic(filepath.Join(stateDirectory, proxyctlMarkerName), managed, 0o600); err != nil {
			return err
		}
	} else {
		previous := filepath.Join(stateDirectory, proxyctlPreviousName)
		if previousInfo, previousErr := os.Lstat(previous); previousErr == nil {
			// The original destination remains intact because replacement is a
			// same-filesystem atomic rename. Do not copy or overwrite it here.
			if !previousInfo.Mode().IsRegular() || previousInfo.Mode()&os.ModeSymlink != 0 {
				return errors.New("previous proxyctl recovery copy is unsafe")
			}
		} else if !errors.Is(previousErr, os.ErrNotExist) {
			return previousErr
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(stateDirectory)
}

func readProxyctlMarker(path string) (proxyctlManaged, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		return proxyctlManaged{}, errors.New("managed proxyctl marker is missing or unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return proxyctlManaged{}, err
	}
	var marker proxyctlManaged
	if err := json.Unmarshal(data, &marker); err != nil || marker.Version != 1 || marker.Owner != "jellyfin-proxy" || len(marker.Current) != 64 || marker.Release == "" {
		return proxyctlManaged{}, errors.New("managed proxyctl marker is invalid")
	}
	return marker, nil
}

func copyAtomic(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.CreateTemp(filepath.Dir(destination), ".proxyctl-*.tmp")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer os.Remove(temporary)
	if err := output.Chmod(mode); err != nil {
		output.Close()
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicReplace(path, data, mode)
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
