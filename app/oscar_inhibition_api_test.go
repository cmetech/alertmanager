package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedInhibitionAppWiring(t *testing.T) {
	opts := testOptions(t)
	opts.InhibitionKey = []byte("dedicated-secret")
	opts.ConversionAdmissionKeys = map[string][]byte{"webhookreceiver/v1": bytes.Repeat([]byte("w"), 32)}
	opts.ConversionCallbackKey = bytes.Repeat([]byte("c"), 32)
	opts.SilenceMutationKey = bytes.Repeat([]byte("s"), 32)
	opts.RoutePrefix = "/native"
	a, err := New(opts)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Stop(t.Context())) })
	// Invoke the real app's mounted handler without starting listeners or services.
	handler := a.servers[0].Handler
	capability := httptest.NewRecorder()
	handler.ServeHTTP(capability, httptest.NewRequest(http.MethodGet, "http://native/native/api/v2/oscar/fingerprint-conversion-capability", nil))
	require.Equal(t, http.StatusOK, capability.Code, capability.Body.String())
	var advertised struct {
		Actors []string `json:"actors"`
	}
	require.NoError(t, json.Unmarshal(capability.Body.Bytes(), &advertised))
	require.Equal(t, []string{"webhookreceiver/v1"}, advertised.Actors)
	silence := httptest.NewRecorder()
	handler.ServeHTTP(silence, httptest.NewRequest(http.MethodPost, "http://native/native/api/v2/silences", bytes.NewBufferString("{}")))
	require.Equal(t, http.StatusForbidden, silence.Code)
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
