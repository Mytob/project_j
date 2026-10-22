package containerhealth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRemoveUnusedApplicationImagesProtectsReleasesContainersAndOtherImages(t *testing.T) {
	oldID := "sha256:" + strings.Repeat("a", 64)
	activeID := "sha256:" + strings.Repeat("b", 64)
	previousID := "sha256:" + strings.Repeat("c", 64)
	usedID := "sha256:" + strings.Repeat("d", 64)
	sharedID := "sha256:" + strings.Repeat("e", 64)
	var deleted []string
	observer := New("/unused")
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/version":
			return jsonResponse(`{"ApiVersion":"1.52","MinAPIVersion":"1.44"}`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1.44/images/json":
			filters, err := url.QueryUnescape(request.URL.Query().Get("filters"))
			if err != nil || !strings.Contains(filters, managedLabel) || request.URL.Query().Get("all") != "1" {
				t.Fatalf("image query was not bounded to all managed images: %q", request.URL.RequestURI())
			}
			return jsonResponse(`[
  {"Id":"` + oldID + `","RepoTags":["jellyfin-proxy/admin:1.5.0-dev"],"Labels":{"jellyfin.proxy.role":"application"}},
  {"Id":"` + activeID + `","RepoTags":["jellyfin-proxy/admin:1.6.0-dev.9"],"Labels":{"jellyfin.proxy.role":"application"}},
  {"Id":"` + previousID + `","RepoTags":["jellyfin-proxy/caddy:1.6.0-dev.7"],"Labels":{"jellyfin.proxy.role":"application"}},
  {"Id":"` + usedID + `","RepoTags":["jellyfin-proxy/security:1.5.0-dev"],"Labels":{"jellyfin.proxy.role":"application"}},
  {"Id":"` + sharedID + `","RepoTags":["jellyfin-proxy/wireguard:1.4.0-dev","custom/wireguard:latest"],"Labels":{"jellyfin.proxy.role":"application"}},
  {"Id":"sha256:` + strings.Repeat("f", 64) + `","RepoTags":["unrelated/app:latest"],"Labels":{"owner":"user"}}
]`), nil
		case request.Method == http.MethodGet && request.URL.Path == "/v1.44/containers/json":
			if request.URL.Query().Get("all") != "1" {
				t.Fatalf("container query did not include stopped containers: %s", request.URL.RequestURI())
			}
			return jsonResponse(`[{"ImageID":"` + usedID + `"}]`), nil
		case request.Method == http.MethodDelete:
			deleted = append(deleted, request.URL.Path)
			if request.URL.Query().Get("force") != "false" || request.URL.Query().Get("noprune") != "false" {
				t.Fatalf("unsafe image deletion query: %s", request.URL.RequestURI())
			}
			return jsonResponse(`[]`), nil
		default:
			t.Fatalf("unexpected Docker request %s %s", request.Method, request.URL.RequestURI())
			return nil, nil
		}
	})}

	result, err := observer.RemoveUnusedApplicationImages(context.Background(), []string{
		"jellyfin-proxy/admin:1.6.0-dev.9",
		"jellyfin-proxy/caddy:1.6.0-dev.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemovedImages != 1 || result.KeptImages != 4 || len(deleted) != 1 || deleted[0] != "/v1.44/images/"+oldID {
		t.Fatalf("image cleanup removed an unsafe set: result=%+v deleted=%v", result, deleted)
	}
}

func TestRemoveUnusedApplicationImagesFailsClosedBeforeDockerAccess(t *testing.T) {
	observer := New("/unused")
	requests := 0
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		t.Fatalf("Docker request made for invalid protected refs: %s", request.URL.RequestURI())
		return nil, nil
	})}
	for _, references := range [][]string{
		{},
		{"alpine:3.24.2"},
		{"jellyfin-proxy/admin:1.6.0-dev.9", "jellyfin-proxy/unknown:latest"},
	} {
		if _, err := observer.RemoveUnusedApplicationImages(context.Background(), references); err == nil {
			t.Errorf("invalid protected references %q were accepted", references)
		}
	}
	if requests != 0 {
		t.Fatalf("Docker API received %d requests for invalid protected references", requests)
	}
}

func TestRemoveUnusedApplicationImagesDoesNotDeleteWhenContainerInventoryFails(t *testing.T) {
	observer := New("/unused")
	deletes := 0
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodDelete {
			deletes++
		}
		switch request.URL.Path {
		case "/version":
			return jsonResponse(`{"ApiVersion":"1.52","MinAPIVersion":"1.44"}`), nil
		case "/v1.44/images/json":
			return jsonResponse(`[]`), nil
		case "/v1.44/containers/json":
			return nil, context.DeadlineExceeded
		default:
			t.Fatalf("unexpected Docker request %s", request.URL.RequestURI())
			return nil, nil
		}
	})}
	if _, err := observer.RemoveUnusedApplicationImages(context.Background(), []string{"jellyfin-proxy/admin:1.6.0-dev.9"}); err == nil {
		t.Fatal("cleanup succeeded without a complete container inventory")
	}
	if deletes != 0 {
		t.Fatalf("cleanup deleted %d images without a complete container inventory", deletes)
	}
}
