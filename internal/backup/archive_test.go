package backup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/monitoring"
	"github.com/Mytob/project_j/internal/webcontent"
)

func TestCreateValidateAndExtractConsistentBackup(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"config", "data", "site", "data/statistics"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"config/admin.json":    "credential hash",
		"config/totp.key":      "totp key",
		"data/whitelist.json":  "[]",
		"data/totp-state.json": `{"version":1,"status":"unconfigured"}`,
		"site/index.html":      "<h1>Jellyfin Proxy</h1>",
		"compose.yaml":         "services: {}\n",
		".env":                 "DOMAIN=example.test\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	history, err := monitoring.OpenHistory(filepath.Join(root, "data", "statistics"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if err := history.Append(monitoring.Snapshot{CapturedAt: at}); err != nil {
		t.Fatal(err)
	}
	if err := history.Close(); err != nil {
		t.Fatal(err)
	}
	archiveDirectory := filepath.Join(t.TempDir(), "operator-directory")
	if err := os.Mkdir(archiveDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archiveDirectory, "state.bak")
	manifest, err := Create(CreateOptions{InstallRoot: root, OutputPath: archive, Version: "1.6.0", BuildID: "testbuild", DatabaseSchema: 1, CreatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(archiveDirectory); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("custom backup changed its parent directory permissions: %v, %v", info, err)
	}
	if manifest.FormatVersion != FormatVersion || len(manifest.Files) != len(files)+1 {
		t.Fatalf("manifest = %+v", manifest)
	}
	if info, err := os.Stat(archive); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode/info = %v, %v", info, err)
	}
	if _, err := os.Stat(archive + ".sha256"); err != nil {
		t.Fatal(err)
	}
	validated, err := Validate(archive)
	if err != nil {
		t.Fatal(err)
	}
	if validated.Version != "1.6.0" {
		t.Fatalf("backup version = %s", validated.Version)
	}
	restore := filepath.Join(t.TempDir(), "restore")
	if _, err := Extract(archive, restore); err != nil {
		t.Fatal(err)
	}
	for name, contents := range files {
		got, err := os.ReadFile(filepath.Join(restore, name))
		if err != nil || string(got) != contents {
			t.Fatalf("restored %s = %q, %v", name, got, err)
		}
	}
	restoredDB, err := monitoring.OpenHistory(filepath.Join(restore, "data", "statistics"))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredDB.Close()
	if rows := restoredDB.Range(at.Add(-time.Minute), at.Add(time.Minute), 10); len(rows) != 1 {
		t.Fatalf("restored stats samples = %d", len(rows))
	}
}

func TestBackupExcludesTemporaryReleasePackageUploads(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"config", "data/package-uploads", "site"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, contents := range map[string]string{
		"config/admin.json":    "credential hash",
		"config/totp.key":     "totp key",
		"data/whitelist.json": "[]",
		"data/totp-state.json": `{"version":1,"status":"unconfigured"}`,
		"data/keep.json":      "persistent data",
		"site/index.html":     "Jellyfin Proxy",
		"compose.yaml":        "services: {}\n",
		".env":                "DOMAIN=example.test\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "data", "package-uploads", "candidate.pkg"), bytes.Repeat([]byte("package"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data", "package-uploads", "upload.json"), []byte(`{"upload":"temporary"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "without-uploads.bak")
	manifest, err := Create(CreateOptions{InstallRoot: root, OutputPath: archive, Version: "1.6.0", BuildID: "testbuild", DatabaseSchema: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range manifest.Files {
		if strings.HasPrefix(item.Path, "data/package-uploads/") {
			t.Fatalf("temporary package upload included in backup manifest: %s", item.Path)
		}
	}
	if _, err := Validate(archive); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := Extract(archive, restored); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(restored, "data", "package-uploads")); !os.IsNotExist(err) {
		t.Fatalf("temporary package upload directory was restored: %v", err)
	}
	if contents, err := os.ReadFile(filepath.Join(restored, "data", "keep.json")); err != nil || string(contents) != "persistent data" {
		t.Fatalf("persistent data was not retained: %q, %v", contents, err)
	}
}

func TestBackupReconstructsValidatedWebContentPointers(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"config", "data", "site", "data/site-content"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, contents := range map[string]string{
		"config/admin.json":    "credential hash",
		"config/totp.key":      "totp key",
		"data/whitelist.json":  "[]",
		"data/totp-state.json": `{"version":1,"status":"unconfigured"}`,
		"site/index.html":      "packaged page",
		"compose.yaml":         "services: {}\n",
		".env":                 "DOMAIN=example.test\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contentRoot := filepath.Join(root, "data", "site-content")
	if err := webcontent.Initialize(contentRoot, filepath.Join(root, "site")); err != nil {
		t.Fatal(err)
	}
	archiveBytes := new(bytes.Buffer)
	zipWriter := zip.NewWriter(archiveBytes)
	page, err := zipWriter.Create("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := page.Write([]byte("custom page")); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := webcontent.PublishZip(contentRoot, bytes.NewReader(archiveBytes.Bytes()), int64(archiveBytes.Len())); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "site.bak")
	manifest, err := Create(CreateOptions{InstallRoot: root, OutputPath: archive, Version: "1.6.0", BuildID: "testbuild", DatabaseSchema: 1})
	if err != nil {
		t.Fatal(err)
	}
	var pointerMetadataFound bool
	var currentRevision string
	for _, item := range manifest.Files {
		if item.Path == "data/site-content/"+webcontent.BackupPointersFile {
			pointerMetadataFound = true
		}
		if item.Path == "data/site-content/current" || item.Path == "data/site-content/previous" {
			t.Fatalf("backup stored pointer as a file: %s", item.Path)
		}
	}
	if !pointerMetadataFound {
		t.Fatal("backup omitted validated web-content pointer metadata")
	}
	if _, err := Validate(archive); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err := Extract(archive, restored); err != nil {
		t.Fatal(err)
	}
	currentRevision, err = os.Readlink(filepath.Join(restored, "data", "site-content", "current"))
	if err != nil || !strings.HasPrefix(filepath.ToSlash(currentRevision), "revisions/") {
		t.Fatalf("restored public-site current pointer = %q, %v", currentRevision, err)
	}
	actual, err := os.ReadFile(filepath.Join(restored, "data", "site-content", "current", "index.html"))
	if err != nil || string(actual) != "custom page" {
		t.Fatalf("restored public homepage = %q, %v", actual, err)
	}
	if _, err := os.Stat(filepath.Join(restored, "data", "site-content", webcontent.BackupPointersFile)); !os.IsNotExist(err) {
		t.Fatalf("internal pointer metadata remains after extraction: %v", err)
	}
}

func TestValidateRejectsUnsafePathsAndCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsafe.bak")
	data := []byte("outside")
	digest := sha256.Sum256(data)
	manifest := Manifest{FormatVersion: FormatVersion, CreatedAt: time.Now().UTC(), Version: "1.6.0", BuildID: "testbuild", DatabaseSchema: 1, Files: []File{{Path: "../escape", Mode: 0o600, Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])}}}
	if err := writeTestArchive(path, manifest, map[string][]byte{"../escape": data}); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(path); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
	if err := os.WriteFile(path, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(path); err == nil {
		t.Fatal("corrupt backup was accepted")
	}
}

func writeTestArchive(path string, manifest Manifest, files map[string][]byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(file)
	writer := tar.NewWriter(gz)
	data, err := json.Marshal(manifest)
	if err == nil {
		err = writer.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg})
	}
	if err == nil {
		_, err = writer.Write(data)
	}
	for name, contents := range files {
		if err == nil {
			err = writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents)), Typeflag: tar.TypeReg})
		}
		if err == nil {
			_, err = writer.Write(contents)
		}
	}
	if closeErr := writer.Close(); err == nil {
		err = closeErr
	}
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}
