package containerhealth

import (
	"context"
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
		if request.URL.Path == "/v1.41/containers/json" {
			filters, err := url.QueryUnescape(request.URL.Query().Get("filters"))
			if err != nil || !strings.Contains(filters, managedLabel) {
				t.Fatalf("Docker container list is not filtered to managed services: %q", filters)
			}
			return jsonResponse(`[{"Id":"admin-id","Labels":{"com.docker.compose.service":"admin","jellyfin.proxy.role":"application"}},{"Id":"other-id","Labels":{"com.docker.compose.service":"other"}}]`), nil
		}
		if request.URL.Path == "/v1.41/containers/admin-id/json" {
			return jsonResponse(`{"Config":{"Labels":{"jellyfin.proxy.role":"application"},"Env":["SECRET=value"],"Image":"private-image"},"State":{"Status":"running","StartedAt":"2026-10-16T11:00:00Z","Health":{"Status":"healthy"}},"RestartCount":3}`), nil
		}
		t.Fatalf("unexpected Docker API request %s", request.URL.RequestURI())
		return nil, nil
	})}
	items, err := observer.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Service != "admin" || items[0].State != "running" || items[0].Health != "healthy" || items[0].RestartCount != 3 || !items[0].StartedAt.Equal(time.Date(2026, 10, 16, 11, 0, 0, 0, time.UTC)) || len(paths) != 2 {
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

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}
