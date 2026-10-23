package maintenance

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrJobAlreadyRunning = errors.New("a maintenance operation is already running")

type Job struct {
	ID          string    `json:"id"`
	Action      string    `json:"action"`
	State       string    `json:"state"`
	Step        int       `json:"step"`
	Total       int       `json:"total"`
	Message     string    `json:"message"`
	Result      string    `json:"result,omitempty"`
	Error       string    `json:"error,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

type JobManager struct {
	operationGate sync.RWMutex
	mu            sync.Mutex
	dir           string
	jobs          map[string]Job
	initErr       error
}

func NewJobManager(directory string) *JobManager {
	m := &JobManager{dir: directory, jobs: make(map[string]Job)}
	m.initErr = m.load()
	return m
}

func (m *JobManager) StartBackup(run func() (string, error)) (Job, error) {
	if run == nil {
		return Job{}, errors.New("backup job requires an operation")
	}
	return m.StartOperation("backup", 2, func(progress func(int, string)) (string, error) {
		progress(1, "Creating and verifying backup")
		return run()
	})
}

// StartOperation durably queues one allowlisted maintenance operation and
// persists its bounded progress. The callback receives no HTTP or filesystem
// input other than values already validated by the maintenance handler.
func (m *JobManager) StartOperation(action string, total int, run func(func(int, string)) (string, error)) (Job, error) {
	return m.StartOperationWithCompletion(action, total, run, nil)
}

// StartOperationWithCompletion runs a fixed operation and invokes its optional
// completion hook only after the terminal job state has been durably written.
// The hook is intended for narrowly scoped follow-up work that must not stop the
// operation process before its result is available to clients.
func (m *JobManager) StartOperationWithCompletion(action string, total int, run func(func(int, string)) (string, error), completion func(Job) error) (Job, error) {
	if !validJobAction(action) || total <= 0 || total > 20 || run == nil {
		return Job{}, errors.New("maintenance job request is invalid")
	}
	m.operationGate.Lock()
	defer m.operationGate.Unlock()
	m.mu.Lock()
	if m.initErr != nil {
		defer m.mu.Unlock()
		return Job{}, errors.New("maintenance job store is unavailable")
	}
	for _, job := range m.jobs {
		if job.State == "queued" || job.State == "running" {
			m.mu.Unlock()
			return Job{}, ErrJobAlreadyRunning
		}
	}
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		m.mu.Unlock()
		return Job{}, errors.New("could not allocate a maintenance job")
	}
	now := time.Now().UTC()
	job := Job{ID: hex.EncodeToString(randomID[:]), Action: action, State: "queued", Total: total, Message: action + " queued", StartedAt: now, UpdatedAt: now}
	if err := m.persist(job); err != nil {
		m.mu.Unlock()
		return Job{}, errors.New("could not persist the maintenance job")
	}
	m.jobs[job.ID] = job
	m.trimLocked()
	m.mu.Unlock()
	go m.runOperation(job.ID, run, completion)
	return job, nil
}

func (m *JobManager) HasActiveOperation() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, job := range m.jobs {
		if job.State == "queued" || job.State == "running" {
			return true
		}
	}
	return false
}

func (m *JobManager) lockRecovery() func() {
	m.operationGate.RLock()
	return m.operationGate.RUnlock
}

func (m *JobManager) Get(id string) (Job, bool) {
	if len(id) != 32 {
		return Job{}, false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return Job{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	return job, ok
}

func (m *JobManager) List() []Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	values := make([]Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		values = append(values, job)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].UpdatedAt.After(values[j].UpdatedAt) })
	if len(values) > 100 {
		values = values[:100]
	}
	return values
}

func (m *JobManager) runOperation(id string, run func(func(int, string)) (string, error), completion func(Job) error) {
	m.change(id, func(job *Job) {
		job.State = "running"
		job.Message = "Starting " + job.Action
	})
	result, err := run(func(step int, message string) {
		m.change(id, func(job *Job) {
			if step < 0 || step > job.Total || len(message) == 0 || len(message) > 200 || strings.ContainsAny(message, "\r\n") {
				return
			}
			job.Step = step
			job.Message = message
		})
	})
	if err != nil {
		m.change(id, func(job *Job) {
			job.State = "failed"
			job.Message = operationTitle(job.Action) + " failed"
			job.Error = cleanJobError(err)
			job.CompletedAt = time.Now().UTC()
		})
	} else {
		m.change(id, func(job *Job) {
			job.State = "completed"
			job.Step = job.Total
			if job.Action == "backup" {
				job.Message = "Backup created and verified"
			} else {
				job.Message = operationTitle(job.Action) + " completed"
			}
			job.Result = result
			job.CompletedAt = time.Now().UTC()
		})
	}
	if completion != nil {
		job, ok := m.Get(id)
		if ok {
			if completionErr := completion(job); completionErr != nil {
				m.change(id, func(job *Job) {
					job.State = "failed"
					job.Message = operationTitle(job.Action) + " finished but a required service refresh failed"
					job.Error = cleanJobError(completionErr)
					if job.CompletedAt.IsZero() {
						job.CompletedAt = time.Now().UTC()
					}
				})
			}
		}
	}
}

func operationTitle(action string) string {
	if action == "" {
		return "Maintenance operation"
	}
	return strings.ToUpper(action[:1]) + action[1:]
}

func (m *JobManager) change(id string, update func(*Job)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	job, ok := m.jobs[id]
	if !ok {
		return
	}
	update(&job)
	job.UpdatedAt = time.Now().UTC()
	if err := m.persist(job); err != nil {
		job.State = "failed"
		job.Message = "Maintenance job state could not be saved"
		job.Error = "persistent job storage failed"
		job.CompletedAt = time.Now().UTC()
		_ = m.persist(job)
	}
	m.jobs[id] = job
}

func (m *JobManager) load() error {
	if !filepath.IsAbs(m.dir) || m.dir == "/" {
		return errors.New("maintenance job directory must be an absolute non-root path")
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(m.dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("maintenance job directory is not a real directory")
	}
	if err := os.Chmod(m.dir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	if len(entries) > 512 {
		return errors.New("maintenance job store exceeds its item limit")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".job-") && strings.HasSuffix(entry.Name(), ".tmp") {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("maintenance job store contains an unsafe temporary entry")
			}
			if err := os.Remove(filepath.Join(m.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("maintenance job store contains an unsupported entry")
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if len(id) != 32 {
			return errors.New("maintenance job store contains an invalid record name")
		}
		if _, err := hex.DecodeString(id); err != nil {
			return errors.New("maintenance job store contains an invalid record name")
		}
		path := filepath.Join(m.dir, entry.Name())
		fileInfo, err := os.Lstat(path)
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Size() > 16<<10 || fileInfo.Mode().Perm()&0o077 != 0 {
			return errors.New("maintenance job record is not a protected regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		var job Job
		decoder := json.NewDecoder(io.LimitReader(file, 16<<10))
		decodeErr := decoder.Decode(&job)
		var extra any
		if decodeErr == nil {
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				decodeErr = errors.New("trailing data")
			}
		}
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil || job.ID != id || !validJobAction(job.Action) || !validJobState(job.State) || job.Total <= 0 || job.Total > 20 || job.Step < 0 || job.Step > job.Total || len(job.Message) > 200 || len(job.Result) > 255 || len(job.Error) > 240 || job.StartedAt.IsZero() || job.UpdatedAt.IsZero() {
			return errors.New("maintenance job record is invalid")
		}
		if job.State == "queued" || job.State == "running" {
			job.State = "failed"
			job.Message = "Operation interrupted when maintenance restarted"
			job.Error = "operation did not finish before service restart"
			job.CompletedAt = time.Now().UTC()
			job.UpdatedAt = job.CompletedAt
			if err := m.write(job); err != nil {
				return err
			}
		}
		m.jobs[id] = job
	}
	return nil
}

func validJobState(state string) bool {
	return state == "queued" || state == "running" || state == "completed" || state == "failed"
}

func validJobAction(action string) bool {
	switch action {
	case "backup", "cleanup", "update", "restore", "rollback":
		return true
	default:
		return false
	}
}

func cleanJobError(err error) string {
	value := strings.TrimSpace(err.Error())
	if value == "" || len(value) > 240 || strings.ContainsAny(value, "\r\n") {
		return "maintenance operation failed; check the maintenance service log"
	}
	return value
}

func (m *JobManager) persist(job Job) error {
	if err := m.write(job); err != nil {
		return fmt.Errorf("persist job state: %w", err)
	}
	return nil
}

func (m *JobManager) write(job Job) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	temp := filepath.Join(m.dir, ".job-"+hex.EncodeToString(suffix[:])+".tmp")
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, filepath.Join(m.dir, job.ID+".json")); err != nil {
		_ = os.Remove(temp)
		return err
	}
	directory, err := os.Open(m.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *JobManager) trimLocked() {
	if len(m.jobs) <= 100 {
		return
	}
	finished := make([]Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		if job.State == "completed" || job.State == "failed" {
			finished = append(finished, job)
		}
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].UpdatedAt.Before(finished[j].UpdatedAt) })
	for len(m.jobs) > 100 && len(finished) > 0 {
		oldest := finished[0]
		finished = finished[1:]
		delete(m.jobs, oldest.ID)
		_ = os.Remove(filepath.Join(m.dir, oldest.ID+".json"))
	}
}
