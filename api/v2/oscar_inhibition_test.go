package v2

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/config"
)

func TestOscarInhibitionGuard(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/api/v2/oscar/inhibition/status", "/api/v2/oscar/inhibition/rules", "/api/v2/oscar/inhibition/validate", "/api/v2//oscar/inhibition/status", "/api/v2/oscar/../oscar/inhibition/status", "/api/v2/oscar/%69nhibition/status", "/api/v2/oscar/inhibition/unknown"} {
		for _, key := range []string{"", "wrong", "secret"} {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
			h := oscarInhibitionGuard(next, []byte("secret"))
			r := httptest.NewRequest("GET", p, nil)
			r.Header.Set("X-Oscar-Inhibition-Key", key)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 403
			if key == "secret" {
				want = 204
			}
			require.Equal(t, want, w.Code, p)
			if want == 403 {
				require.Equal(t, "application/json", w.Header().Get("Content-Type"))
				require.Contains(t, w.Body.String(), `"code":"forbidden"`)
			}
		}
	}
	w := httptest.NewRecorder()
	oscarInhibitionGuard(http.NotFoundHandler(), nil).ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/inhibition/status", nil))
	require.Equal(t, 403, w.Code)
}

func TestOscarInhibitionAPI(t *testing.T) {
	t.Parallel()
	c := config.NewCoordinator("unused", prometheus.NewRegistry(), promslog.NewNopLogger())
	require.NoError(t, c.EnableManagedInhibition(filepath.Join(t.TempDir(), "managed.json"), "test"))
	c.Subscribe(func(*config.Config) error { return nil })
	base, err := config.Load("route:\n  receiver: test\nreceivers:\n- name: test\n")
	require.NoError(t, err)
	require.NoError(t, c.ApplyConfig(base))
	h := ManagedInhibitionHandler(http.NotFoundHandler(), c, []byte("secret"))
	call := func(method, endpoint, body, etag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v2/oscar/inhibition/"+endpoint, bytes.NewBufferString(body))
		r.Header.Set("X-Oscar-Inhibition-Key", "secret")
		r.Header.Set("If-Match", etag)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	status := call("GET", "status", "", "")
	require.Equal(t, 200, status.Code)
	var initial config.ManagedInhibitionStatus
	require.NoError(t, json.Unmarshal(status.Body.Bytes(), &initial))
	require.Equal(t, initial.ETag, status.Header().Get("ETag"))
	for _, body := range []string{`{}`, `{"rules":null}`, `{"rules":[],"unknown":1}`, `{"rules":[]} {}`, `{"rules":[{"name":"invalid"}]}`} {
		require.Equal(t, 400, call("POST", "validate", body, "").Code, body)
	}
	require.Equal(t, 200, call("POST", "validate", `{"rules":[]}`, "").Code)
	require.Equal(t, 428, call("PUT", "rules", `{"rules":[]}`, "").Code)
	require.Equal(t, 412, call("PUT", "rules", `{"rules":[]}`, `"stale"`).Code)
	require.Equal(t, 200, call("PUT", "rules", `{"rules":[]}`, initial.ETag).Code)
	require.Equal(t, 405, call("POST", "status", `{}`, "").Code)
	require.Equal(t, 413, call("POST", "validate", string(bytes.Repeat([]byte(" "), config.ManagedInhibitionMaxBodyBytes+1)), "").Code)
}

func TestOscarInhibitionMatcherValuePresence(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"source_matchers", "target_matchers"} {
		for _, value := range []string{"missing", "null", "empty"} {
			for _, operation := range []struct{ method, path string }{{http.MethodPost, "validate"}, {http.MethodPut, "rules"}} {
				t.Run(side+"/"+value+"/"+operation.path, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "managed.json")
					c := config.NewCoordinator("unused", prometheus.NewRegistry(), promslog.NewNopLogger())
					require.NoError(t, c.EnableManagedInhibition(path, "test"))
					calls := 0
					c.Subscribe(func(*config.Config) error { calls++; return nil })
					base, err := config.Load("route:\n  receiver: test\nreceivers:\n- name: test\n")
					require.NoError(t, err)
					require.NoError(t, c.ApplyConfig(base))
					_, err = c.ApplyManagedInhibition(c.ManagedInhibitionStatus().ETag, config.ManagedInhibitionSet{})
					require.NoError(t, err)
					before := c.ManagedInhibitionStatus()
					diskBefore, err := os.ReadFile(path)
					require.NoError(t, err)
					callsBefore := calls
					source := map[string]any{"label": "alertname", "operator": "=", "value": "Parent"}
					target := map[string]any{"label": "alertname", "operator": "!=", "value": "Child"}
					matcher := source
					if side == "target_matchers" {
						matcher = target
					}
					switch value {
					case "missing":
						delete(matcher, "value")
					case "null":
						matcher["value"] = nil
					case "empty":
						matcher["value"] = ""
					}
					body, err := json.Marshal(map[string]any{"rules": []any{map[string]any{"name": "oscar-inh-1-r1", "source_matchers": []any{source}, "target_matchers": []any{target}, "equal": []string{"site"}}}})
					require.NoError(t, err)
					req := httptest.NewRequest(operation.method, "/api/v2/oscar/inhibition/"+operation.path, bytes.NewReader(body))
					req.Header.Set("X-Oscar-Inhibition-Key", "secret")
					req.Header.Set("If-Match", before.ETag)
					response := httptest.NewRecorder()
					ManagedInhibitionHandler(http.NotFoundHandler(), c, []byte("secret")).ServeHTTP(response, req)
					if value == "empty" {
						require.Equal(t, http.StatusOK, response.Code, response.Body.String())
						var canonical struct {
							Rules []config.ManagedInhibitionRule `json:"rules"`
						}
						require.NoError(t, json.Unmarshal(response.Body.Bytes(), &canonical))
						require.Len(t, canonical.Rules, 1)
						matchers := canonical.Rules[0].SourceMatchers
						if side == "target_matchers" {
							matchers = canonical.Rules[0].TargetMatchers
						}
						require.Contains(t, matchers, config.ManagedInhibitionMatcher{Label: "alertname", Operator: matcher["operator"].(string), Value: ""})
						return
					}
					require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
					var failure struct {
						Code   string                                    `json:"code"`
						Errors []config.ManagedInhibitionValidationError `json:"errors"`
					}
					require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
					require.Equal(t, "validation_failed", failure.Code)
					require.Len(t, failure.Errors, 1)
					require.Equal(t, "rules.0."+side+".0.value", failure.Errors[0].Field)
					require.Equal(t, before, c.ManagedInhibitionStatus())
					require.Equal(t, callsBefore, calls)
					diskAfter, err := os.ReadFile(path)
					require.NoError(t, err)
					require.Equal(t, diskBefore, diskAfter)
				})
			}
		}
	}
}
