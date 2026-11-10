package v2

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
		{"create wrong key", "POST", "/api/v2/silences", "wrong", http.StatusForbidden},
		{"create with key", "POST", "/api/v2/silences", string(key), http.StatusNoContent},
		{"end without key", "DELETE", "/api/v2/silence/a-b-c", "", http.StatusForbidden},
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
