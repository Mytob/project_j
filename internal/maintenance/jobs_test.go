package maintenance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupJobPersistsProgressAndResult(t *testing.T) {
	manager := NewJobManager(filepath.Join(t.TempDir(), "jobs"))
	started, err := manager.StartBackup(func() (string, error) { return "backup.bak", nil })
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var finished Job
	for time.Now().Before(deadline) {
		finished, _ = manager.Get(started.ID)
		if finished.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if finished.State != "completed" || finished.Result != "backup.bak" || finished.Step != finished.Total {
		t.Fatalf("completed job = %+v", finished)
	}
	reloaded := NewJobManager(manager.dir)
	persisted, ok := reloaded.Get(started.ID)
	if !ok || persisted.State != "completed" || persisted.Result != "backup.bak" {
		t.Fatalf("persisted job = %+v, found=%v", persisted, ok)
	}
}

func TestOperationCompletionHookRunsAfterTerminalStateIsPersisted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "jobs")
	manager := NewJobManager(dir)
	completed := make(chan Job, 1)
	started, err := manager.StartOperationWithCompletion("update", 2, func(progress func(int, string)) (string, error) {
		progress(1, "Updating release")
		return "1.6.0-dev.2", nil
	}, func(job Job) error {
		reloaded := NewJobManager(dir)
		persisted, ok := reloaded.Get(job.ID)
		if !ok || persisted.State != "completed" || persisted.Result != "1.6.0-dev.2" {
			return fmt.Errorf("completion hook ran before terminal state persisted: %+v, found=%v", persisted, ok)
		}
		completed <- job
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case job := <-completed:
		if job.State != "completed" || job.ID != started.ID {
			t.Fatalf("completion hook received job %+v", job)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completion hook did not run")
	}
}

func TestOnlyOneActiveMaintenanceJobRuns(t *testing.T) {
	manager := NewJobManager(filepath.Join(t.TempDir(), "jobs"))
	release := make(chan struct{})
	started, err := manager.StartBackup(func() (string, error) {
		<-release
		return "backup.bak", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			job, ok := manager.Get(started.ID)
			if ok && (job.State == "completed" || job.State == "failed") {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Errorf("maintenance worker did not persist a terminal state before cleanup: %+v", func() Job {
			job, _ := manager.Get(started.ID)
			return job
		}())
	}()
	if _, err := manager.StartBackup(func() (string, error) { return "", nil }); err != ErrJobAlreadyRunning {
		t.Fatalf("second active job error = %v, want %v", err, ErrJobAlreadyRunning)
	}
	if job, ok := manager.Get(started.ID); !ok || (job.State != "queued" && job.State != "running") {
		t.Fatalf("first job state = %+v, found=%v", job, ok)
	}
}

func TestActiveJobIsMarkedInterruptedAfterRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "jobs")
	manager := NewJobManager(dir)
	job := Job{ID: "0123456789abcdef0123456789abcdef", Action: "backup", State: "running", Total: 2, Message: "Creating backup", StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := manager.persist(job); err != nil {
		t.Fatal(err)
	}
	reloaded := NewJobManager(dir)
	got, ok := reloaded.Get(job.ID)
	if !ok || got.State != "failed" || got.CompletedAt.IsZero() || got.Error == "" {
		t.Fatalf("recovered interrupted job = %+v, found=%v", got, ok)
	}
}

func TestJobStoreRejectsSymlinksAndRemovesOrphanedTemporaryFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "jobs")
	manager := NewJobManager(dir)
	if manager.initErr != nil {
		t.Fatal(manager.initErr)
	}
	temporary := filepath.Join(dir, ".job-abcd.tmp")
	if err := os.WriteFile(temporary, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded := NewJobManager(dir)
	if reloaded.initErr != nil {
		t.Fatal(reloaded.initErr)
	}
	if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
		t.Fatalf("orphaned temporary state still exists: %v", err)
	}
}
