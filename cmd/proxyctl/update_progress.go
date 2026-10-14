package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Mytob/project_j/internal/deployment"
)

// newUpdateProgressReporter renders milestone completion and a live spinner
// while long Docker or readiness operations are running.
func newUpdateProgressReporter(output io.Writer) (func(deployment.UpdateProgress), func(bool)) {
	file, ok := output.(*os.File)
	terminal := false
	if ok {
		if info, err := file.Stat(); err == nil {
			terminal = info.Mode()&os.ModeCharDevice != 0
		}
	}

	var mu sync.Mutex
	stop := make(chan struct{})
	stopped := make(chan struct{})
	var current deployment.UpdateProgress
	started := time.Time{}
	active := false
	spin := 0

	draw := func() {
		percent := updateProgressPercent(current)
		elapsed := time.Since(started).Round(time.Second)
		mark := "✓"
		if active {
			mark = string("|/-\\"[spin%4])
		}
		fmt.Fprintf(output, "\r[%s] %3d%% %s %s (%s)", updateProgressBar(percent, 20), percent, current.Message, mark, elapsed)
	}
	interval := time.Second
	if !terminal {
		interval = 15 * time.Second
	}
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				mu.Lock()
				if active {
					if terminal {
						spin++
						draw()
					} else {
						elapsed := time.Since(started).Round(time.Second)
						fmt.Fprintf(output, "Still working (%s, %d%% milestones complete): %s\n", elapsed, updateProgressPercent(current), current.Message)
					}
				}
				mu.Unlock()
			}
		}
	}()

	report := func(progress deployment.UpdateProgress) {
		mu.Lock()
		defer mu.Unlock()
		current = progress
		if progress.Done {
			active = false
			if started.IsZero() {
				started = time.Now()
			}
			if terminal {
				draw()
				fmt.Fprintln(output)
			} else {
				percent := updateProgressPercent(progress)
				fmt.Fprintf(output, "[%s] %3d%% complete: %s\n", updateProgressBar(percent, 20), percent, progress.Message)
			}
			return
		}
		started = time.Now()
		spin = 0
		active = true
		if terminal {
			draw()
		} else {
			percent := updateProgressPercent(progress)
			fmt.Fprintf(output, "[%s] %3d%% in progress: %s\n", updateProgressBar(percent, 20), percent, progress.Message)
		}
	}
	finish := func(success bool) {
		close(stop)
		<-stopped
		mu.Lock()
		defer mu.Unlock()
		if active {
			active = false
			if terminal {
				fmt.Fprintln(output)
			}
			if !success {
				fmt.Fprintln(output, "Update stopped before all milestones completed; see the error below.")
			}
		}
	}
	return report, finish
}

func updateProgressPercent(progress deployment.UpdateProgress) int {
	if progress.Total <= 0 {
		return 0
	}
	completed := progress.Step - 1
	if progress.Done {
		completed = progress.Step
	}
	if completed < 0 {
		completed = 0
	}
	if completed > progress.Total {
		completed = progress.Total
	}
	return completed * 100 / progress.Total
}

func updateProgressBar(percent, width int) string {
	if width < 1 {
		return ""
	}
	filled := percent * width / 100
	if filled > width {
		filled = width
	}
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}
