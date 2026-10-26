package maintenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mytob/project_j/internal/containerhealth"
)

type fakeRecoveryRuntime struct {
	snapshots []containerhealth.Snapshot
	restarts  []string
	restartErr error
}

func (f *fakeRecoveryRuntime) Snapshot(context.Context) ([]containerhealth.Snapshot, error) {
	return append([]containerhealth.Snapshot(nil), f.snapshots...), nil
}

func (f *fakeRecoveryRuntime) Restart(_ context.Context, service string) error {
	f.restarts = append(f.restarts, service)
	return f.restartErr
}

func TestRecoveryControllerUsesPersistentProgressiveBackoffAndStopsAtLimit(t *testing.T) {
	root := t.TempDir()
	jobs := NewJobManager(filepath.Join(root, "jobs"))
	runtime := &fakeRecoveryRuntime{snapshots: []containerhealth.Snapshot{
		{Service: "admin", State: "running", Health: "unhealthy"},
		{Service: "caddy", State: "running", Health: "healthy"},
		{Service: "hostmetrics", State: "running", Health: "healthy"},
		{Service: "securityd", State: "running", Health: "healthy"},
		{Service: "wireguard", State: "running", Health: "healthy"},
	}}
	path := filepath.Join(root, "state", "recovery.json")
	controller, err := NewRecoveryController(runtime, jobs, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	controller.now = func() time.Time { return now }
	for attempt := 1; attempt <= recoveryAttemptLimit; attempt++ {
		if attempt > 1 {
			status := controller.Status()
			now = status.Services[0].NextAttemptAt.Add(time.Second)
		}
		if err := controller.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		status := controller.Status()
		if status.Services[0].Attempts != attempt || status.Services[0].Stopped {
			t.Fatalf("recovery state after attempt %d = %+v", attempt, status.Services[0])
		}
		if status.Services[0].NextAttemptAt.Sub(now) != recoveryBackoff(attempt) {
			t.Fatalf("retry delay after attempt %d = %s", attempt, status.Services[0].NextAttemptAt.Sub(now))
		}
	}
	if len(runtime.restarts) != recoveryAttemptLimit {
		t.Fatalf("restart calls = %v, want %d attempts", runtime.restarts, recoveryAttemptLimit)
	}
	now = controller.Status().Services[0].NextAttemptAt.Add(time.Second)
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := controller.Status()
	if !status.Services[0].Stopped || status.Services[0].LastAction != "retry_limit_reached" || len(runtime.restarts) != recoveryAttemptLimit {
		t.Fatalf("recovery did not stop after its limit: service=%+v calls=%v", status.Services[0], runtime.restarts)
	}
	reopened, err := NewRecoveryController(runtime, jobs, path)
	if err != nil {
		t.Fatal(err)
	}
	restored := reopened.Status()
	if !restored.Services[0].Stopped || restored.Services[0].Attempts != recoveryAttemptLimit || len(restored.Events) != recoveryAttemptLimit*2+1 {
		t.Fatalf("recovery state did not persist across controller restart: %+v", restored)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery state file permissions = %v, %v", info, err)
	}
	encoded, err := json.Marshal(restored)
	if err != nil || len(encoded) > 256<<10 {
		t.Fatalf("recovery status exceeds its bound: %d, %v", len(encoded), err)
	}
}

func TestRecoveryDoesNotRestartHealthyServicesOrRaceMaintenanceJobs(t *testing.T) {
	root := t.TempDir()
	jobs := NewJobManager(filepath.Join(root, "jobs"))
	runtime := &fakeRecoveryRuntime{snapshots: []containerhealth.Snapshot{{Service: "admin", State: "running", Health: "healthy"}}}
	controller, err := NewRecoveryController(runtime, jobs, filepath.Join(root, "state", "recovery.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.restarts) != 0 {
		t.Fatalf("healthy service was restarted: %v", runtime.restarts)
	}

	runtime.snapshots = []containerhealth.Snapshot{{Service: "admin", State: "exited", Health: "none"}}
	blocked := make(chan struct{})
	job, err := jobs.StartOperation("backup", 2, func(func(int, string)) (string, error) {
		<-blocked
		return "backup.bak", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runtime.restarts) != 0 || !controller.Status().OperationActive {
		t.Fatalf("automatic recovery interfered with a maintenance job: restarts=%v status=%+v", runtime.restarts, controller.Status())
	}
	close(blocked)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if current, ok := jobs.Get(job.ID); ok && current.State == "completed" {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("maintenance job did not complete after recovery check: %+v", jobs.List())
}

func TestRecoveryDoesNotRestartWhenDockerHasNoFailureEvidence(t *testing.T) {
	for _, snapshot := range []containerhealth.Snapshot{
		{Service: "admin", State: "unknown", Health: "unknown"},
		{Service: "admin", State: "created", Health: "none"},
		{Service: "admin", State: "paused", Health: "none"},
		{Service: "admin", State: "restarting", Health: "unhealthy"},
		{Service: "admin", State: "running", Health: "unknown"},
	} {
		t.Run(snapshot.State+"/"+snapshot.Health, func(t *testing.T) {
			root := t.TempDir()
			runtime := &fakeRecoveryRuntime{snapshots: []containerhealth.Snapshot{snapshot}}
			controller, err := NewRecoveryController(runtime, NewJobManager(filepath.Join(root, "jobs")), filepath.Join(root, "state", "recovery.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := controller.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(runtime.restarts) != 0 || controller.Status().Services[0].Attempts != 0 {
				t.Fatalf("recovery acted without Docker failure evidence: snapshots=%+v status=%+v", runtime.snapshots, controller.Status().Services[0])
			}
		})
	}
}

func TestRecoveryRejectsUnsafeStateAndUnapprovedServices(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"services":{"other":{"service":"other"}},"events":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecoveryController(&fakeRecoveryRuntime{}, NewJobManager(filepath.Join(root, "jobs")), path); err == nil {
		t.Fatal("accepted an unapproved service in recovery state")
	}
	controller, err := NewRecoveryController(&fakeRecoveryRuntime{}, NewJobManager(filepath.Join(root, "jobs2")), filepath.Join(root, "other.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(controller.Status().Services) != len(recoverableServices) {
		t.Fatalf("recovery exposed an unexpected service list: %+v", controller.Status().Services)
	}
}

func TestFreshRecoveryStatusSerializesEmptyEventsAsArray(t *testing.T) {
	root := t.TempDir()
	controller, err := NewRecoveryController(&fakeRecoveryRuntime{}, NewJobManager(filepath.Join(root, "jobs")), filepath.Join(root, "state", "recovery.json"))
	if err != nil {
		t.Fatal(err)
	}
	status := controller.Status()
	if status.Events == nil || status.Services == nil {
		t.Fatalf("fresh recovery collections must be empty arrays, got services=%#v events=%#v", status.Services, status.Events)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded["events"]) != "[]" {
		t.Fatalf("fresh recovery events JSON = %s, want []", decoded["events"])
	}
}
