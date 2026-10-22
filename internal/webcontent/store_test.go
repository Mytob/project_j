package webcontent

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishZipAddsDefaultErrorsAndRollbackRestoresPriorRevision(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public")
	defaultDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(defaultDir, "index.html"), []byte("default home"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, defaultDir); err != nil {
		t.Fatal(err)
	}
	status, err := GetStatus(root)
	if err != nil || status.Current != "default" || status.Previous != "" {
		t.Fatalf("initial content status = %+v, %v", status, err)
	}
	archive := makeZip(t, map[string][]byte{"index.html": []byte("custom home"), "assets/site.css": []byte("body{color:#fff}"), "errors/403.html": []byte("custom denied")})
	status, err = PublishZip(root, bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if status.Current == "default" || status.Previous != "default" {
		t.Fatalf("published revisions = %+v", status)
	}
	assertContent(t, root, status.Current, "index.html", "custom home")
	assertContent(t, root, status.Current, "errors/403.html", "custom denied")
	assertContent(t, root, status.Current, "errors/404.html", defaultErrors["404.html"])
	status, err = Rollback(root)
	if err != nil {
		t.Fatal(err)
	}
	if status.Current != "default" || status.Previous == "" || status.Previous == "default" {
		t.Fatalf("rollback revisions = %+v", status)
	}
	assertContent(t, root, "default", "index.html", "default home")
}

func TestPublishZipRejectsUnsafeAndNonStaticArchivesWithoutChangingCurrent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public")
	defaultDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(defaultDir, "index.html"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, defaultDir); err != nil {
		t.Fatal(err)
	}
	badArchives := map[string][]byte{
		"traversal":      makeZip(t, map[string][]byte{"../escape.html": []byte("bad"), "index.html": []byte("bad")}),
		"absolute":       makeZip(t, map[string][]byte{"/outside.html": []byte("bad"), "index.html": []byte("bad")}),
		"server-side":    makeZip(t, map[string][]byte{"index.html": []byte("bad"), "run.php": []byte("bad")}),
		"duplicate-case": makeZipEntries(t, []zipEntry{{name: "index.html", content: "one"}, {name: "INDEX.HTML", content: "two"}}),
	}
	for name, archive := range badArchives {
		t.Run(name, func(t *testing.T) {
			if _, err := PublishZip(root, bytes.NewReader(archive), int64(len(archive))); err == nil {
				t.Fatal("unsafe web content archive was accepted")
			}
			status, err := GetStatus(root)
			if err != nil || status.Current != "default" {
				t.Fatalf("failed upload changed active site: %+v, %v", status, err)
			}
		})
	}
}

func TestPublishZipRejectsSymlinksAndMissingHomepage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public")
	defaultDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(defaultDir, "index.html"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(root, defaultDir); err != nil {
		t.Fatal(err)
	}
	for name, archive := range map[string][]byte{
		"no-index": makeZip(t, map[string][]byte{"about.html": []byte("missing homepage")}),
		"symlink":  makeSymlinkZip(t),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PublishZip(root, bytes.NewReader(archive), int64(len(archive))); err == nil {
				t.Fatal("archive without a safe homepage was accepted")
			}
		})
	}
}

func TestPublishZipEnforcesCompressedAndExpandedLimits(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public")
	tooLarge := make([]byte, MaxArchiveBytes+1)
	if _, err := PublishZip(root, bytes.NewReader(tooLarge), int64(len(tooLarge))); err == nil {
		t.Fatal("oversized archive was accepted")
	}
	large := bytes.Repeat([]byte("a"), int(MaxExpandedBytes+1))
	archive := makeZip(t, map[string][]byte{"index.html": large})
	if _, err := PublishZip(root, bytes.NewReader(archive), int64(len(archive))); err == nil {
		t.Fatal("expanded-size limit was not enforced")
	}
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	entries := make([]zipEntry, 0, len(files))
	for name, content := range files {
		entries = append(entries, zipEntry{name: name, content: string(content)})
	}
	return makeZipEntries(t, entries)
}

type zipEntry struct {
	name    string
	content string
	mode    os.FileMode
}

func makeZipEntries(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(file, strings.NewReader(entry.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func makeSymlinkZip(t *testing.T) []byte {
	t.Helper()
	return makeZipEntries(t, []zipEntry{{name: "index.html", content: "safe"}, {name: "assets/linked.html", content: "index.html", mode: os.ModeSymlink | 0o777}})
}

func assertContent(t *testing.T, root, revision, name, want string) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(root, "revisions", revision, filepath.FromSlash(name)))
	if err != nil || string(contents) != want {
		t.Fatalf("revision %s file %s = %q, %v; want %q", revision, name, contents, err, want)
	}
}
