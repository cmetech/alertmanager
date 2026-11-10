package v2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	silence_ops "github.com/prometheus/alertmanager/api/v2/restapi/operations/silence"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestOscarSilenceMutationGuard(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	forwarded := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusNoContent)
	})
	guard := oscarSilenceMutationGuard(next, key)
	tests := []struct {
		name, method, path, supplied string
		want                         int
	}{
		{"create without key", "POST", "/api/v2/silences", "", http.StatusForbidden},
		{"create trailing slash", "POST", "/api/v2/silences/", "", http.StatusForbidden},
		{"create doubled slash", "POST", "//api/v2/silences", "", http.StatusForbidden},
		{"create encoded path", "POST", "/api/v2/%73ilences", "", http.StatusForbidden},
		{"create wrong key", "POST", "/api/v2/silences", "wrong", http.StatusForbidden},
		{"create with key", "POST", "/api/v2/silences", string(key), http.StatusNoContent},
		{"end without key", "DELETE", "/api/v2/silence/a-b-c", "", http.StatusForbidden},
		{"end trailing slash", "DELETE", "/api/v2/silence/a-b-c/", "", http.StatusForbidden},
		{"end with key", "DELETE", "/api/v2/silence/a-b-c", string(key), http.StatusNoContent},
		{"read silences", "GET", "/api/v2/silences", "", http.StatusNoContent},
		{"read one", "GET", "/api/v2/silence/a-b-c", "", http.StatusNoContent},
		{"ingest alert", "POST", "/api/v2/alerts", "", http.StatusNoContent},
		{"other post", "POST", "/api/v2/status", "", http.StatusNoContent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.supplied != "" {
				req.Header.Set(oscarSilenceMutationHeader, tc.supplied)
			}
			resp := httptest.NewRecorder()
			before := forwarded
			guard.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status=%d, want=%d", resp.Code, tc.want)
			}
			if tc.want == http.StatusForbidden && forwarded != before {
				t.Fatal("forbidden mutation reached native handler")
			}
			if strings.Contains(resp.Body.String(), string(key)) {
				t.Fatal("response leaked mutation key")
			}
		})
	}
}

func TestOscarNativeAPIHTTPGuard(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry(), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/api/v2/silences", "/api/v2/silences/", "//api/v2/silences", "/api/v2/%73ilences"} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
		resp := httptest.NewRecorder()
		api.Handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusForbidden {
			t.Errorf("POST %s returned %d, want 403", target, resp.Code)
		}
	}
	for _, target := range []string{"/api/v2/silence/abc", "/api/v2/silence/abc/"} {
		req := httptest.NewRequest(http.MethodDelete, target, nil)
		resp := httptest.NewRecorder()
		api.Handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusForbidden {
			t.Errorf("DELETE %s returned %d, want 403", target, resp.Code)
		}
	}
	for _, target := range []string{"/api/v2/silences", "/api/v2/alerts"} {
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{"))
		req.Header.Set(oscarSilenceMutationHeader, string(key))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		api.Handler.ServeHTTP(resp, req)
		if resp.Code == http.StatusForbidden {
			t.Errorf("authorized POST %s was forbidden", target)
		}
	}
}

func TestOscarSilenceMutationHandlersRejectWithoutKey(t *testing.T) {
	api := &API{silenceMutationKey: []byte("0123456789abcdef0123456789abcdef")}
	post := httptest.NewRecorder()
	api.postSilencesHandler(silence_ops.PostSilencesParams{HTTPRequest: httptest.NewRequest(http.MethodPost, "/api/v2/silences/", nil)}).WriteResponse(post, runtime.JSONProducer())
	if post.Code != http.StatusForbidden {
		t.Fatalf("post status=%d, want forbidden", post.Code)
	}
	deleteResp := httptest.NewRecorder()
	api.deleteSilenceHandler(silence_ops.DeleteSilenceParams{HTTPRequest: httptest.NewRequest(http.MethodDelete, "/api/v2/silence/id/", nil)}).WriteResponse(deleteResp, runtime.JSONProducer())
	if deleteResp.Code != http.StatusForbidden {
		t.Fatalf("delete status=%d, want forbidden", deleteResp.Code)
	}
}
