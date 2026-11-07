package v2

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/provider/mem"
	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"
)

func TestOscarGridFilterBeforeCountAndPage(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	now := time.Now().UTC()
	for i, name := range []string{"Straße", "STRASSE", "other"} {
		severity := model.LabelValue("critical")
		if i == 1 {
			severity = "warning"
		}
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": model.LabelValue(name), "instance": model.LabelValue(string(rune('a' + i))), "severity": severity}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		require.NoError(t, alerts.Put(t.Context(), a))
	}
	query := url.Values{"grid_filter": {`{"items":[{"field":"alertname","operator":"equals","value":"STRASSE"}],"logicOperator":"and"}`}, "perPage": {"1"}}
	w := httptest.NewRecorder()
	api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page?"+query.Encode(), nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	var page struct {
		ContractVersion int               `json:"contract_version"`
		TotalRecords    int               `json:"total_records"`
		TotalPages      int               `json:"total_pages"`
		Records         []json.RawMessage `json:"records"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, 2, page.ContractVersion)
	require.Equal(t, 2, page.TotalRecords)
	require.Equal(t, 2, page.TotalPages)
	require.Len(t, page.Records, 1)
	query.Set("base_filter", `{"items":[{"field":"severity","operator":"equals","value":"critical"}]}`)
	w = httptest.NewRecorder()
	api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page?"+query.Encode(), nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Equal(t, 1, page.TotalRecords)
	require.Equal(t, 1, page.TotalPages)
}

func TestOscarGridModelBoundaries(t *testing.T) {
	folded := func(model string) oscarGridModel {
		t.Helper()
		m, err := parseOscarGridModel(model)
		require.NoError(t, err)
		return m
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	a := alert.New(model.Alert{
		Labels:      model.LabelSet{"alertname": "Straße", "instance": "one", "site": "WEST"},
		Annotations: model.LabelSet{"summary": ""},
		StartsAt:    now.Add(500 * time.Microsecond), EndsAt: now.Add(time.Hour),
	}, now, false)
	status := alert.AlertStatus{State: alert.AlertStateActive}
	fp := a.Fingerprint().String()
	for name, tc := range map[string]struct {
		filter string
		match  bool
	}{
		"empty OR":               {`{"items":[],"logicOperator":"or"}`, true},
		"casefold":               {`{"items":[{"field":"alertname","operator":"equals","value":"STRASSE"}]}`, true},
		"absent negative":        {`{"items":[{"field":"severity","operator":"doesNotContain","value":"critical"}]}`, true},
		"present empty":          {`{"items":[{"field":"summary","operator":"isEmpty"}]}`, false},
		"present empty notEmpty": {`{"items":[{"field":"summary","operator":"isNotEmpty"}]}`, true},
		"label negative present": {`{"items":[{"field":"label_any:site,missing","operator":"doesNotContain","value":"east"}]}`, true},
		"label negative absent":  {`{"items":[{"field":"label_any:missing,other","operator":"doesNotContain","value":"east"}]}`, false},
		"OR":                     {`{"items":[{"field":"instance","operator":"equals","value":"wrong"},{"field":"alertname","operator":"equals","value":"strasse"}],"logicOperator":"or"}`, true},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.match, folded(tc.filter).matches(a, status, fp, now))
		})
	}
	date := now.Format(time.RFC3339Nano)
	require.True(t, folded(`{"items":[{"field":"starts_at","operator":"onOrBefore","value":"`+date+`"}]}`).matches(a, status, fp, now))
	require.False(t, folded(`{"items":[{"field":"starts_at","operator":"after","value":"`+date+`"}]}`).matches(a, status, fp, now))
	require.True(t, folded(`{"items":[{"field":"starts_at","operator":"between","value":["`+now.Add(time.Second).Format(time.RFC3339Nano)+`","`+date+`"]}]}`).matches(a, status, fp, now))
	for _, raw := range []string{`{"items":null}`, `{"items":[{"field":"incident_id","operator":"equals","value":"x"}]}`, `{"items":[{"field":"starts_at","operator":"contains","value":"x"}]}`, `{"items":[{"field":"label:","operator":"isEmpty"}]}`} {
		_, err := parseOscarGridModel(raw)
		require.Error(t, err, raw)
	}
	_, err := parseOscarGridModel(`{"items":[{"field":"label_any:site,,,,,,,,","operator":"equals","value":"west"}]}`)
	require.NoError(t, err, "empty label segments do not count toward the eight-name cap")
}

func TestOscarGridFrozenPythonCorpus(t *testing.T) {
	data, err := os.ReadFile("testdata/active_native_corpus.json")
	require.NoError(t, err)
	var corpus struct {
		WireRows []struct {
			Fingerprint string            `json:"fingerprint"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"wire_rows"`
		InternalTimes map[string]struct {
			StartsAt  string `json:"startsAt"`
			EndsAt    string `json:"endsAt"`
			UpdatedAt string `json:"updatedAt"`
		} `json:"internal_times"`
		Cases []struct {
			Name         string   `json:"name"`
			Canonical    *string  `json:"canonical"`
			Status       int      `json:"status"`
			Fingerprints []string `json:"fingerprints"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &corpus))
	alerts, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	ids := map[string]string{}
	for _, row := range corpus.WireRows {
		internal := corpus.InternalTimes[row.Fingerprint]
		starts, err := time.Parse(time.RFC3339Nano, internal.StartsAt)
		require.NoError(t, err)
		ends, err := time.Parse(time.RFC3339Nano, internal.EndsAt)
		require.NoError(t, err)
		updated, err := time.Parse(time.RFC3339Nano, internal.UpdatedAt)
		require.NoError(t, err)
		ls, annotations := model.LabelSet{}, model.LabelSet{}
		for k, v := range row.Labels {
			ls[model.LabelName(k)] = model.LabelValue(v)
		}
		for k, v := range row.Annotations {
			annotations[model.LabelName(k)] = model.LabelValue(v)
		}
		a := alert.New(model.Alert{Labels: ls, Annotations: annotations, StartsAt: starts, EndsAt: ends}, updated, false)
		require.NoError(t, alerts.Put(t.Context(), a))
		ids[a.Fingerprint().String()] = row.Fingerprint
	}
	for _, tc := range corpus.Cases {
		if tc.Status != 200 {
			continue
		} // Public Python validation covers errors.
		t.Run(tc.Name, func(t *testing.T) {
			q := url.Values{"perPage": {"100"}}
			if tc.Canonical != nil {
				q.Set("grid_filter", *tc.Canonical)
			}
			w := httptest.NewRecorder()
			api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page?"+q.Encode(), nil))
			require.Equal(t, 200, w.Code, w.Body.String())
			var page struct {
				Total   int `json:"total_records"`
				Records []struct {
					Fingerprint string `json:"fingerprint"`
				} `json:"records"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
			got := []string{}
			for _, row := range page.Records {
				got = append(got, ids[row.Fingerprint])
			}
			slices.Sort(got)
			require.Equal(t, tc.Fingerprints, got)
			require.Equal(t, len(tc.Fingerprints), page.Total)
		})
	}
}
