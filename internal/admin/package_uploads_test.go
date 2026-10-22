package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPackageUploadStoreResumesAndCompletesWithIndependentChecksum(t *testing.T) {
	store, err := NewPackageUploadStore(filepath.Join(t.TempDir(), "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("self-contained release package")
	created, err := store.Create("jellyfin-proxy-1.6.0.pkg", int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if created.TotalChunks != 1 || len(created.Received) != 0 || created.Complete {
		t.Fatalf("new upload status = %+v", created)
	}
	if _, err := store.PutChunk(created.ID, 0, bytes.NewReader(content[:8])); err == nil {
		t.Fatal("accepted an undersized chunk")
	}
	status, err := store.PutChunk(created.ID, 0, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Received) != 1 || status.Received[0] != 0 {
		t.Fatalf("resumable chunk status = %+v", status)
	}
	if _, err := store.Complete(created.ID, "bad-checksum"); err == nil {
		t.Fatal("accepted a malformed checksum")
	}
	if _, err := store.Complete(created.ID, hex.EncodeToString(make([]byte, sha256.Size))); err == nil {
		t.Fatal("accepted a well-formed but incorrect checksum")
	}
	sha := sha256.Sum256(content)
	status, err = store.Complete(created.ID, hex.EncodeToString(sha[:]))
	if err != nil {
		t.Fatal(err)
	}
	if !status.Complete || status.SHA256 != hex.EncodeToString(sha[:]) || len(status.Received) != 0 {
		t.Fatalf("completed upload status = %+v", status)
	}
	path, err := store.PackagePath(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("completed package = %q, %v", got, err)
	}
	if _, err := store.Complete(created.ID, hex.EncodeToString(sha[:])); err != nil {
		t.Fatalf("idempotent completion = %v", err)
	}
	if _, err := store.PackagePath("../../etc/passwd"); err == nil {
		t.Fatal("accepted a path as an upload ID")
	}
}

func TestPackageUploadStorePersistsResumeStateAndExpiresOldUploads(t *testing.T) {
	store, err := NewPackageUploadStore(filepath.Join(t.TempDir(), "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	content := []byte("restart-safe chunk")
	upload, err := store.Create("candidate.pkg", int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutChunk(upload.ID, 0, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewPackageUploadStore(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return now }
	resumed, err := reopened.Status(upload.ID)
	if err != nil || len(resumed.Received) != 1 || resumed.Received[0] != 0 {
		t.Fatalf("recovered upload = %+v, %v", resumed, err)
	}
	record, err := reopened.readRecord(upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.UpdatedAt = now.Add(-packageUploadMaxAge - time.Second)
	if err := reopened.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := reopened.cleanupLocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Status(upload.ID); err == nil {
		t.Fatalf("expired upload still available: %v", err)
	}
	if _, err := os.Stat(reopened.chunkPath(upload.ID, 0)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired upload chunk still exists: %v", err)
	}
}

func TestPackageUploadStoreRejectsUnsafeConfigurationAndRecords(t *testing.T) {
	if _, err := NewPackageUploadStore(filepath.Join(string(os.PathSeparator))); err == nil {
		t.Fatal("accepted filesystem root as upload directory")
	}
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, err := NewPackageUploadStore(link); err == nil {
		t.Fatal("accepted symlink upload directory")
	}
	store, err := NewPackageUploadStore(filepath.Join(root, "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create("../escape.pkg", 1); err == nil {
		t.Fatal("accepted a path as the package filename")
	}
	if _, err := store.Create("release.pkg", packageUploadMaxBytes+1); err == nil {
		t.Fatal("accepted an oversized package")
	}
}
