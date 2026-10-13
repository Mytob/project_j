package main

import "testing"

func TestBumpPatchVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		increment int
		want      string
	}{
		{name: "stable release", version: "1.0.0", increment: 1, want: "1.0.1"},
		{name: "development release", version: "1.0.0-dev", increment: 2, want: "1.0.2-dev"},
		{name: "prerelease and build metadata", version: "1.2.9-rc.1+build.7", increment: 1, want: "1.2.10-rc.1+build.7"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := bumpPatchVersion(test.version, test.increment)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("bumpPatchVersion(%q, %d) = %q, want %q", test.version, test.increment, got, test.want)
			}
		})
	}
}

func TestBumpPatchVersionRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		version   string
		increment int
	}{
		{version: "1.0", increment: 1},
		{version: "1.0.x", increment: 1},
		{version: "1.0.0", increment: 0},
	} {
		if _, err := bumpPatchVersion(test.version, test.increment); err == nil {
			t.Errorf("bumpPatchVersion(%q, %d) unexpectedly succeeded", test.version, test.increment)
		}
	}
}
