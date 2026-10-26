package containerhealth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestSnapshotUsesReadOnlyFilteredDockerCallsAndReturnsOnlyHealthFields(t *testing.T) {
	var paths []string
	observer := New("/unused")
	observer.now = func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("Docker API method = %s, want GET", request.Method)
		}
		paths = append(paths, request.URL.RequestURI())
		if request.URL.Path == "/version" {
			return jsonResponse(`{"ApiVersion":"1.52","MinAPIVersion":"1.41"}`), nil
		}
		if request.URL.Path == "/v1.41/containers/json" {
			filters, err := url.QueryUnescape(request.URL.Query().Get("filters"))
			if err != nil || !strings.Contains(filters, managedLabel) {
				t.Fatalf("Docker container list is not filtered to managed services: %q", filters)
			}
			return jsonResponse(`[{"Id":"admin-id","Labels":{"com.docker.compose.service":"admin","jellyfin.proxy.role":"application"}},{"Id":"other-id","Labels":{"com.docker.compose.service":"other"}}]`), nil
		}
		if request.URL.Path == "/v1.41/containers/admin-id/json" {
			return jsonResponse(`{"Config":{"Labels":{"jellyfin.proxy.role":"application"},"Env":["SECRET=value"],"Image":"registry.invalid/jp/caddy:1.6.0-dev"},"State":{"Status":"running","StartedAt":"2026-10-16T11:00:00Z","Health":{"Status":"healthy"}},"RestartCount":3}`), nil
		}
		t.Fatalf("unexpected Docker API request %s", request.URL.RequestURI())
		return nil, nil
	})}
	items, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Service != "admin" || items[0].State != "running" || items[0].Health != "healthy" || items[0].RestartCount != 3 || items[0].Image != "registry.invalid/jp/caddy:1.6.0-dev" || !items[0].StartedAt.Equal(time.Date(2026, 10, 16, 11, 0, 0, 0, time.UTC)) || len(paths) != 3 {
		t.Fatalf("unexpected container snapshots or request count: %#v, %v", items, paths)
	}
	response := httptest.NewRecorder()
	observer.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/containers", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health response status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "SECRET") || strings.Contains(response.Body.String(), "private-image") || !strings.Contains(response.Body.String(), `"restart_count":3`) {
		t.Fatalf("observer leaked non-health Docker fields or omitted health data: %s", response.Body.String())
	}
}

func TestInventoryReturnsOnlyManagedComponentVersionInformation(t *testing.T) {
	observer := New("/unused")
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("Docker API method = %s, want GET", request.Method)
		}
		switch request.URL.Path {
		case "/version":
			return jsonResponse(`{"Version":"29.1.3","ApiVersion":"1.52","MinAPIVersion":"1.44"}`), nil
		case "/v1.44/containers/json":
			return jsonResponse(`[{"Id":"caddy-id","Labels":{"com.docker.compose.service":"caddy","jellyfin.proxy.role":"application"}}]`), nil
		case "/v1.44/containers/caddy-id/json":
			return jsonResponse(`{"Config":{"Image":"jellyfin-proxy/caddy:1.6.0-dev","Labels":{"jellyfin.proxy.role":"application","jellyfin.proxy.component-version":"2.11.7"},"Env":["SECRET=value"],"Mounts":["/private"]},"State":{"Status":"running"},"RestartCount":0}`), nil
		default:
			t.Fatalf("unexpected Docker API request %s", request.URL.RequestURI())
			return nil, nil
		}
	})}
	inventory, err := observer.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inventory.DockerEngineVersion != "29.1.3" || len(inventory.Services) != 1 || inventory.Services[0].Service != "caddy" || inventory.Services[0].Image != "jellyfin-proxy/caddy:1.6.0-dev" || inventory.Services[0].ComponentVersion != "2.11.7" {
		t.Fatalf("unexpected runtime inventory: %+v", inventory)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "/private") || strings.Contains(string(encoded), "Env") {
		t.Fatalf("runtime inventory leaked private Docker inspect data: %s", encoded)
	}
}

func TestSnapshotNegotiatesDaemonMinimumAndRejectsUnsupportedRanges(t *testing.T) {
	t.Run("new daemon minimum", func(t *testing.T) {
		var paths []string
		observer := New("/unused")
		observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			paths = append(paths, request.URL.Path)
			switch request.URL.Path {
			case "/version":
				return jsonResponse(`{"ApiVersion":"1.52","MinAPIVersion":"1.44"}`), nil
			case "/v1.44/containers/json":
				return jsonResponse(`[]`), nil
			default:
				t.Fatalf("unexpected Docker API request %s", request.URL.Path)
				return nil, nil
			}
		})}
		if _, err := observer.Snapshot(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(paths) != 2 || paths[1] != "/v1.44/containers/json" {
			t.Fatalf("Docker API version was not negotiated: %v", paths)
		}
	})

	t.Run("unsupported daemon range", func(t *testing.T) {
		var paths []string
		observer := New("/unused")
		observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			paths = append(paths, request.URL.Path)
			return jsonResponse(`{"ApiVersion":"1.40","MinAPIVersion":"1.24"}`), nil
		})}
		if _, err := observer.Snapshot(context.Background()); err == nil {
			t.Fatal("expected unsupported Docker API range error")
		}
		if len(paths) != 1 || paths[0] != "/version" {
			t.Fatalf("observer made container requests after unsupported negotiation: %v", paths)
		}
	})

	t.Run("malformed daemon version", func(t *testing.T) {
		for _, advertised := range []string{"+1.52", "1.+52", " 1.52", "1.52 ", "1..52", "1.52.0", "1.-1"} {
			observer := New("/unused")
			observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/version" {
					t.Fatalf("unexpected Docker API request %s", request.URL.Path)
				}
				return jsonResponse(`{"ApiVersion":"` + advertised + `","MinAPIVersion":"1.41"}`), nil
			})}
			if _, err := observer.Snapshot(context.Background()); err == nil {
				t.Errorf("malformed Docker API version %q was accepted", advertised)
			}
		}
	})
}

func TestObserverRejectsNonGetRequestsAndReportsDockerFailure(t *testing.T) {
	observer := New("/unused")
	observer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })}
	handler := observer.Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/containers", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("non-GET status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/containers", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("Docker API failure status = %d", response.Code)
	}
}

func TestRecoveryRestartIsLimitedToExistingManagedComposeService(t *testing.T) {
	var gets, posts []string
	observer := New("/unused")
	observer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("observer lookup method = %s, want GET", request.Method)
		}
		gets = append(gets, request.URL.RequestURI())
		switch request.URL.Path {
		case "/version":
			return jsonResponse(`{"ApiVersion":"1.52","MinAPIVersion":"1.44"}`), nil
		case "/v1.44/containers/json":
			return jsonResponse(`[{"Id":"admin-id","Labels":{"com.docker.compose.service":"admin","jellyfin.proxy.role":"application"}},{"Id":"unrelated-id","Labels":{"com.docker.compose.service":"other","jellyfin.proxy.role":"application"}}]`), nil
		case "/v1.44/containers/admin-id/json":
			return jsonResponse(`{"Config":{"Labels":{"com.docker.compose.service":"admin","jellyfin.proxy.role":"application"}},"State":{"Status":"exited"}}`), nil
		default:
			t.Fatalf("unexpected Docker lookup %s", request.URL.RequestURI())
			return nil, nil
		}
	})}
	observer.restartClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost {
			t.Fatalf("restart method = %s, want POST", request.Method)
		}
		posts = append(posts, request.URL.RequestURI())
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if err := observer.Restart(context.Background(), "other"); err == nil {
		t.Fatal("unapproved Compose service was restartable")
	}
	if len(gets) != 0 || len(posts) != 0 {
		t.Fatalf("unapproved service reached Docker: GET=%v POST=%v", gets, posts)
	}
	if err := observer.Restart(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if len(gets) != 3 || len(posts) != 1 || posts[0] != "/v1.44/containers/admin-id/restart?t=10" {
		t.Fatalf("unexpected Docker recovery calls: GET=%v POST=%v", gets, posts)
	}
}

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
