package app

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestObservationAppActualSinkAndUnavailableStartup(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, valid := range []bool{false, true} {
			t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled]+"/"+map[bool]string{false: "missing-key", true: "valid-key"}[valid], func(t *testing.T) {
				opts := testOptions(t)
				opts.InhibitionKey = []byte("control-key")
				opts.InhibitionObservations = enabled
				opts.InhibitionObservationURL = "http://127.0.0.1:1/api/v1/alerts/internal/inhibition/observations"
				opts.InhibitionObservationKeyFile = filepath.Join(t.TempDir(), "evidence-key")
				if valid {
					require.NoError(t, os.WriteFile(opts.InhibitionObservationKeyFile, []byte(strings.Repeat("k", 32)), 0o600))
				}
				a, err := New(opts)
				require.NoError(t, err, "sink failure must not stop valid base alert processing")
				t.Cleanup(func() { require.NoError(t, a.Stop(t.Context())) })
				req := httptest.NewRequest("GET", "http://native/api/v2/oscar/inhibition/status", nil)
				req.Header.Set("X-Oscar-Inhibition-Key", "control-key")
				response := httptest.NewRecorder()
				a.servers[0].Handler.ServeHTTP(response, req)
				require.Equal(t, 200, response.Code)
				var status struct {
					Recording map[string]any `json:"recording"`
				}
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &status))
				require.Equal(t, enabled, status.Recording["flag_enabled"])
				require.Equal(t, enabled && valid, status.Recording["sink_initialized"])
				require.Equal(t, enabled && valid, status.Recording["interest_active"])
				want := "not_enabled"
				if enabled {
					want = "degraded"
					if valid {
						want = "unknown"
					}
				}
				require.Equal(t, want, status.Recording["state"])
			})
		}
	}
}
