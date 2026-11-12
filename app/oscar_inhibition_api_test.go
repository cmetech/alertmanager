package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedInhibitionAppWiring(t *testing.T) {
	opts := testOptions(t)
	opts.InhibitionKey = []byte("dedicated-secret")
	opts.RoutePrefix = "/native"
	a, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Stop(t.Context())) })
	// Invoke the real app's mounted handler without starting listeners or services.
	handler := a.servers[0].Handler
	for _, key := range []string{"", "wrong", "dedicated-secret"} {
		req := httptest.NewRequest("GET", "http://native/native/api/v2/oscar/inhibition/status", nil)
		req.Header.Set("X-Oscar-Inhibition-Key", key)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		expected := 403
		if key == "dedicated-secret" {
			expected = 200
		}
		require.Equal(t, expected, w.Code, w.Body.String())
		if expected == 200 {
			put := httptest.NewRequest(http.MethodPut, "http://native/native/api/v2/oscar/inhibition/rules", bytes.NewBufferString(`{"rules":[]}`))
			put.Header.Set("X-Oscar-Inhibition-Key", key)
			put.Header.Set("If-Match", w.Header().Get("ETag"))
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, put)
			require.Equal(t, 200, result.Code, result.Body.String())
		}
	}
}
