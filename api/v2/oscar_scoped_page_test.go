// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package v2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/provider/mem"
)

const scopeTestKey = "12345678901234567890123456789012"
const scopeTestPath = "/api/v2/oscar/alerts/scoped-page"

func scopedRequest(body, audience string, now time.Time) *http.Request {
	r := httptest.NewRequest("POST", scopeTestPath, strings.NewReader(body))
	stamp := fmt.Sprint(now.Unix())
	sum := sha256.Sum256([]byte(body))
	mac := hmac.New(sha256.New, []byte(scopeTestKey))
	fmt.Fprintf(mac, "%s\nPOST\n%s\noperator\nv1\n%s\nYWxpY2U\nread:alerts\n%x", audience, scopeTestPath, stamp, sum)
	for name, value := range map[string]string{"Sender": "operator", "Key-Id": "v1", "Time": stamp, "Subject": "YWxpY2U", "Grant": "read:alerts", "Signature": hex.EncodeToString(mac.Sum(nil))} {
		r.Header.Set("X-Oscar-Read-"+name, value)
	}
	return r
}

type scopedRecorder struct {
	*httptest.ResponseRecorder
	deadline func(time.Time) error
}

func newScopedRecorder() *scopedRecorder {
	return &scopedRecorder{ResponseRecorder: httptest.NewRecorder(), deadline: func(time.Time) error { return nil }}
}
func (w *scopedRecorder) SetReadDeadline(t time.Time) error { return w.deadline(t) }

func TestScopedPage(t *testing.T) {
	now := time.Now()
	store, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	api, err := NewAPI(store, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: team\nreceivers:\n- name: team\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	key := filepath.Join(t.TempDir(), "operator")
	require.NoError(t, os.WriteFile(key, []byte(scopeTestKey), 0600))
	require.NoError(t, api.InstallActionOwner(ActionOwnerConfig{OperatorKeyFile: key}))
	require.Nil(t, api.actionOwner)
	handle := func(r *http.Request) *httptest.ResponseRecorder {
		w := newScopedRecorder()
		api.Handler.ServeHTTP(w, r)
		return w.ResponseRecorder
	}
	for _, labels := range []model.LabelSet{
		{"alertname": "aaa", "team": "other", "unicode": "�", "astral": "😀"}, {"alertname": "bbb", "team": "a", "env": "dev"}, {"alertname": "ccc", "team": "a", "env": "prod"},
		{"alertname": "ddd", "team": "b", "oscar_correlation_role": "child", "oscar_correlation_rule_id": "12", "oscar_correlation_parent_fingerprint": "abcd"}, {"alertname": "eee", "team": "b", "correlation_parent_identity": "partial"},
	} {
		require.NoError(t, store.Put(t.Context(), alert.New(model.Alert{Labels: labels, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)))
	}
	group := func(k, v string) string {
		return fmt.Sprintf(`{"items":[{"field":"label:%s","operator":"equals","value":"%s"}]}`, k, v)
	}
	envelope := func(scope, query string) string {
		return fmt.Sprintf(`{"version":1,"scope":%s,"query":%s}`, scope, query)
	}
	scope := fmt.Sprintf(`{"unrestricted":false,"allow":[%s,%s],"deny":[%s]}`, group("team", "a"), group("team", "b"), group("env", "dev"))
	grouped := `{"unrestricted":false,"allow":[{"logicOperator":"and","items":[{"field":"label:team","operator":"equals","value":"a"},{"field":"label:env","operator":"equals","value":"prod"}]},{"logicOperator":"or","items":[{"field":"label:team","operator":"equals","value":"b"},{"field":"label:unrelated","operator":"equals","value":"x"}]}],"deny":[]}`
	body := envelope(scope, `{"perPage":["1"],"column":["alertname"],"order":["asc"]}`)
	const domain = "native-scoped-page-v1"
	for _, tc := range []struct {
		body  string
		total int
		first string
	}{
		{envelope(grouped, `{"order":["asc"],"column":["alertname"],"perPage":["1"]}`), 2, "ccc"},
		{envelope(`{"unrestricted":true,"allow":[],"deny":[{"items":[{"field":"label:env","operator":"isAnyOf","value":["DEV","qa"]}]}]}`, `{}`), 3, ""},
		{body, 2, "ccc"}, {envelope(scope, `{"quick_search":["ddd"]}`), 1, "ddd"},
		{envelope(`{"unrestricted":true,"allow":[],"deny":[]}`, `{}`), 5, ""},
		{envelope(`{"unrestricted":false,"allow":[],"deny":[]}`, `{}`), 0, ""},
	} {
		w := handle(scopedRequest(tc.body, domain, now))
		require.Equal(t, 200, w.Code, w.Body.String())
		var page struct {
			Total   int `json:"total_records"`
			Records []struct {
				Labels      map[string]string
				Fingerprint string
			}
			Timing map[string]any `json:"timing_by_fingerprint"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
		require.Equal(t, tc.total, page.Total)
		if tc.first != "" {
			require.Len(t, page.Records, 1)
			require.Equal(t, tc.first, page.Records[0].Labels["alertname"])
			if tc.first == "ddd" {
				require.Equal(t, "abcd", page.Records[0].Labels["oscar_correlation_parent_fingerprint"])
			}
			require.Len(t, page.Timing, 1)
			require.Contains(t, page.Timing, page.Records[0].Fingerprint)
		}
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		require.Equal(t, "1", w.Header().Get("X-Oscar-Scoped-Page-Version"))
	}
	for _, tc := range []struct {
		literal, key string
		code, total  int
	}{
		{`\ud800`, "unicode", 400, 0}, {`\udc00`, "unicode", 400, 0},
		{`\ud800\u0061`, "unicode", 400, 0}, {`\ud83d\ude00`, "astral", 200, 1},
		{"�", "unicode", 200, 1}, {`\\ud800`, "unicode", 200, 0},
	} {
		wire := envelope(fmt.Sprintf(`{"unrestricted":false,"allow":[%s],"deny":[]}`, group(tc.key, tc.literal)), `{}`)
		w := handle(scopedRequest(wire, domain, now))
		require.Equal(t, tc.code, w.Code, tc.literal)
		if tc.code == 200 {
			var page struct {
				Total int `json:"total_records"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
			require.Equal(t, tc.total, page.Total)
		}
	}
	mutation := httptest.NewRequest("POST", actionPath, strings.NewReader(actionBody))
	stamp := fmt.Sprint(now.Unix())
	mac := hmac.New(sha256.New, []byte(scopeTestKey))
	fmt.Fprintf(mac, "native-action-v1\nPOST\n%s\noperator\nv1\n%s\nYWxpY2U\nupdate:alerts:acknowledge\n%x", actionPath, stamp, sha256.Sum256([]byte(actionBody)))
	for name, value := range map[string]string{"Sender": "operator", "Key-Id": "v1", "Time": stamp, "Subject": "YWxpY2U", "Grant": "update:alerts:acknowledge", "Signature": hex.EncodeToString(mac.Sum(nil))} {
		mutation.Header.Set("X-Oscar-Action-"+name, value)
	}
	require.Equal(t, 401, handle(mutation).Code)
	for _, r := range []*http.Request{
		httptest.NewRequest("POST", scopeTestPath, strings.NewReader(body)),
		scopedRequest(body, "native-action-v1", now),
		scopedRequest(body, domain, now.Add(-time.Minute*2)),
	} {
		require.Equal(t, 401, handle(r).Code)
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("X-Oscar-Read-Subject", "YWxpY2U") },
		func(r *http.Request) { r.Header.Set("X-Oscar-Read-Subject", "Ym9i") },
		func(r *http.Request) { r.URL.RawQuery = "page=2" },
		func(r *http.Request) { r.Header.Set("X-Oscar-Read-Sender", "policy") },
		func(r *http.Request) { r.Body = scopedRequest(body+" ", domain, now).Body },
	} {
		r := scopedRequest(body, domain, now)
		mutate(r)
		require.Equal(t, 401, handle(r).Code)
	}
	for _, invalid := range []string{
		strings.Replace(body, `"unrestricted":false,`, "", 1),
		strings.Replace(body, `"allow":[`, `"allow":[`+strings.Repeat(group("team", "a")+",", 32), 1),
		strings.Replace(body, `"items":[`, `"items":[`+strings.Repeat(`{"field":"label:x","operator":"equals","value":"x"},`, 100), 1),
		strings.Replace(body, `"value":"a"`, `"value":"`+strings.Repeat("x", 4097)+`"`, 1),
		strings.Replace(body, group("team", "a"), `{"items":[{"field":"label:x","operator":"isAnyOf","value":[null]}]}`, 1),
		strings.Replace(body, `"version":1`, `"version":1,"extra":2`, 1),
		strings.Replace(body, `"value":"a"`, `"value":"a","value":"b"`, 1),
		strings.Replace(body, `"value":"a"`, string([]byte{34, 255, 34}), 1),
		strings.Replace(body, "equals", "contains", 1),
		strings.Replace(body, "equals", "isAnyOf", 1),
		strings.Replace(body, `"value":"a"`, `"value":null`, 1),
		strings.Replace(body, `"value":"a"`, `"value":"a","id":2`, 1),
		strings.Replace(body, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(body, group("team", "a"), `{"items":[]}`, 1),
		strings.Replace(body, group("team", "a"), `{"items":[{"field":"label:x","operator":"isAnyOf","value":[]}]}`, 1),
	} {
		require.Equal(t, 400, handle(scopedRequest(invalid, domain, now)).Code, invalid)
	}
	t.Run("body read deadline releases admission", func(t *testing.T) {
		// Exercise more sequential expirations than the eight-slot budget, with peers still open.
		for range 9 {
			server, peer := net.Pipe()
			t.Cleanup(func() { server.Close(); peer.Close() })
			require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
			req := scopedRequest(body, domain, time.Now())
			req.Body = server
			w := newScopedRecorder()
			var deadlines []time.Time
			w.deadline = func(d time.Time) error {
				deadlines = append(deadlines, d)
				if !d.IsZero() {
					d = time.Now().Add(time.Millisecond)
				}
				return server.SetReadDeadline(d)
			}
			api.Handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusRequestTimeout, w.Code)
			require.Len(t, deadlines, 2)
			require.WithinDuration(t, time.Now().Add(5*time.Second), deadlines[0], time.Second)
			require.True(t, deadlines[1].IsZero())
		}
		require.Equal(t, 200, handle(scopedRequest(body, domain, time.Now())).Code)
	})
	require.Equal(t, 413, handle(scopedRequest(strings.Repeat(" ", actionBodyLimit+1), domain, now)).Code)
}

func TestScopeParityFixture(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/oscar_scope_parity_v1.json")
	require.NoError(t, err)
	var cases []struct {
		Name   string
		Labels model.LabelSet
		Group  scopeGroup
		Match  bool
	}
	require.NoError(t, json.Unmarshal(raw, &cases))
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			policy, err := (scopeWire{Allow: []scopeGroup{tc.Group}, Deny: []scopeGroup{}}).compile()
			require.NoError(t, err)
			require.Equal(t, tc.Match, policy.matches(&alert.Alert{Alert: model.Alert{Labels: tc.Labels}}, newOscarCaseFolder()))
		})
	}
}

func TestScopedPageGeneratedRouteRequiresReadGuard(t *testing.T) {
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	const body = `{"version":1,"scope":{"unrestricted":true,"allow":[],"deny":[]},"query":{"perPage":["1"]}}`
	req := scopedRequest(body, "native-scoped-page-v1", time.Now())
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.Handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	require.Empty(t, w.Header().Values("X-Oscar-Scoped-Page-Version"))
}
