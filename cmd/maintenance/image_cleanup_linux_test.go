//go:build linux

package main

import (
	"testing"

	"github.com/Mytob/project_j/internal/release"
)

func TestApplicationImageReferencesSelectsAllFiveProxyImages(t *testing.T) {
	images := []release.Image{
		{Reference: "alpine:3.24.2"},
		{Reference: "jellyfin-proxy/admin:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/caddy:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/hostmetrics:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/security:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/wireguard:1.6.0-dev.9"},
	}
	refs, err := applicationImageReferences(images)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 5 {
		t.Fatalf("application image references = %v, want all five proxy images", refs)
	}
}

func TestApplicationImageReferencesRejectsIncompleteOrDuplicateManifest(t *testing.T) {
	base := []release.Image{
		{Reference: "jellyfin-proxy/admin:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/caddy:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/hostmetrics:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/security:1.6.0-dev.9"},
		{Reference: "jellyfin-proxy/wireguard:1.6.0-dev.9"},
	}
	if _, err := applicationImageReferences(base[:4]); err == nil {
		t.Fatal("incomplete application image manifest was accepted")
	}
	duplicate := append(append([]release.Image(nil), base...), release.Image{Reference: "jellyfin-proxy/admin:1.6.0-dev.8"})
	if _, err := applicationImageReferences(duplicate); err == nil {
		t.Fatal("duplicate application image component was accepted")
	}
}
