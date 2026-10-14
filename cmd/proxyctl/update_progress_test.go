package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Mytob/project_j/internal/deployment"
)

func TestUpdateProgressReporterPrintsMilestonesForNonTerminalOutput(t *testing.T) {
	var output bytes.Buffer
	report, finish := newUpdateProgressReporter(&output)
	report(deployment.UpdateProgress{Step: 1, Total: 8, Message: "Checking installation"})
	report(deployment.UpdateProgress{Step: 1, Total: 8, Message: "Installation healthy", Done: true})
	report(deployment.UpdateProgress{Step: 4, Total: 8, Message: "Loading images"})
	report(deployment.UpdateProgress{Step: 8, Total: 8, Message: "Update completed", Done: true})
	finish(true)
	text := output.String()
	for _, expected := range []string{"  0% in progress: Checking installation", " 12% complete: Installation healthy", " 37% in progress: Loading images", "100% complete: Update completed"} {
		if !strings.Contains(text, expected) {
			t.Errorf("progress output missing %q: %s", expected, text)
		}
	}
}

func TestUpdateProgressPercentageClampsMilestoneCounts(t *testing.T) {
	cases := []struct {
		name string
		in   deployment.UpdateProgress
		want int
	}{
		{name: "first step", in: deployment.UpdateProgress{Step: 1, Total: 8}, want: 0},
		{name: "completed first step", in: deployment.UpdateProgress{Step: 1, Total: 8, Done: true}, want: 12},
		{name: "last active step", in: deployment.UpdateProgress{Step: 8, Total: 8}, want: 87},
		{name: "all complete", in: deployment.UpdateProgress{Step: 8, Total: 8, Done: true}, want: 100},
		{name: "past end", in: deployment.UpdateProgress{Step: 10, Total: 8, Done: true}, want: 100},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := updateProgressPercent(test.in); got != test.want {
				t.Fatalf("updateProgressPercent() = %d, want %d", got, test.want)
			}
		})
	}
}
