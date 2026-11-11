// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package v2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
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
	"github.com/prometheus/alertmanager/inhibit"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/marker"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestOscarPageHTTP(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Minute, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	api.Update(cfg, func(context.Context, labelset.LabelSet) {})
	w := httptest.NewRecorder()
	api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	require.JSONEq(t, `{"contract_version":2,"records":[],"total_records":0,"total_pages":0,"timing_by_fingerprint":{}}`, w.Body.String())
}

func TestOscarPageReportsTimeMuteOnOneOfMultipleRoutes(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Minute, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: fallback\n  routes:\n  - receiver: team\n    matchers: [instance=\"a\"]\n    continue: true\n    mute_time_intervals: [quiet]\n  - receiver: team\n    matchers: [instance=\"a\"]\nreceivers:\n- name: fallback\n- name: team\ntime_intervals:\n- name: quiet\n  time_intervals:\n  - weekdays: [sunday]\n")
	require.NoError(t, err)
	api.Update(cfg, func(ctx context.Context, ls labelset.LabelSet) {
		m, _ := marker.FromContext(ctx)
		m.SetSilenced(ls.Fingerprint(), nil)
	})
	api.PublishTiming(cfg, nil, timingMuter{}, nil)
	now := time.Now().UTC()
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "instance": "a"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	require.NoError(t, alerts.Put(t.Context(), a))
	w := httptest.NewRecorder()
	api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	var page struct {
		Records []struct {
			Status struct {
				State string `json:"state"`
			} `json:"status"`
		} `json:"records"`
		Timing map[string]struct {
			MutedBy []string `json:"muted_by"`
		} `json:"timing_by_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &page))
	require.Len(t, page.Records, 1)
	require.Equal(t, "active", page.Records[0].Status.State)
	require.Equal(t, []string{"quiet"}, page.Timing[a.Fingerprint().String()].MutedBy)
	for _, tc := range []struct {
		state string
		count int
	}{{"active", 1}, {"suppressed", 0}} {
		filter := fmt.Sprintf(`{"items":[{"field":"alert_status","operator":"equals","value":"%s"}]}`, tc.state)
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page?grid_filter="+url.QueryEscape(filter), nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var got struct {
			Total int `json:"total_records"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		require.Equal(t, tc.count, got.Total)
	}
}

func TestOscarPageValidationAndParity(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Minute, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n  labels:\n    owner: team\n")
	require.NoError(t, err)
	api.Update(cfg, func(ctx context.Context, ls labelset.LabelSet) {
		m, _ := marker.FromContext(ctx)
		m.SetSilenced(ls.Fingerprint(), nil)
	})
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i, name := range []string{"Straße", "STRASSE", "C", "D", "E"} {
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": model.LabelValue(name), "instance": model.LabelValue(strconv.Itoa(i)), "severity": "critical"}, Annotations: model.LabelSet{"summary": "hello"}, StartsAt: now.Add(time.Duration(i%2) * 500 * time.Microsecond), EndsAt: now.Add(time.Hour)}, now, false)
		require.NoError(t, alerts.Put(t.Context(), a))
	}
	request := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	for _, query := range []string{"active=maybe", "active=yes", "page=abc", "page=%2B1", "perPage=1e2", "page=0", "page=50001", "perPage=101", "page=", "page=1&page=2", "wat=x", "order=no", "column=no", "receiver=%5B", "filter=%7B", "quick_search=" + strings.Repeat("a", 201)} {
		t.Run(query, func(t *testing.T) {
			w := request("/api/v2/oscar/alerts/page?" + query)
			require.Equal(t, 400, w.Code, w.Body.String())
		})
	}
	type result struct {
		Records []json.RawMessage `json:"records"`
		Total   int               `json:"total_records"`
		Pages   int               `json:"total_pages"`
	}
	get := func(q string) result {
		w := request("/api/v2/oscar/alerts/page?" + q)
		require.Equal(t, 200, w.Code, w.Body.String())
		var p result
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &p))
		return p
	}
	legacy := request("/api/v2/alerts")
	require.Equal(t, 200, legacy.Code, legacy.Body.String())
	var native []json.RawMessage
	require.NoError(t, json.Unmarshal(legacy.Body.Bytes(), &native))
	require.Len(t, native, 5)
	asc := get("column=startsAt&order=asc&perPage=2")
	require.Equal(t, 5, asc.Total)
	require.Equal(t, 3, asc.Pages)
	require.Len(t, asc.Records, 2)
	middle := get("column=startsAt&order=asc&perPage=2&page=2")
	last := get("column=startsAt&order=asc&perPage=2&page=3")
	deep := get("perPage=2&page=50000")
	require.Empty(t, deep.Records)
	require.Equal(t, 5, deep.Total)
	require.Equal(t, 3, deep.Pages)
	all := append(append(asc.Records, middle.Records...), last.Records...)
	require.Equal(t, native, all)
	desc := get("column=startsAt&order=desc&perPage=100")
	slices.Reverse(all)
	require.Equal(t, all, desc.Records)
	require.Equal(t, 5, get("severity=CRITICAL&receiver=default&receiver_matchers=owner%3D%22team%22").Total)
	require.Equal(t, 2, get("quick_search=STRASSE").Total)
	require.Equal(t, 0, get("active=false").Total)
	require.Equal(t, 1, get("filter=instance%3D%220%22").Total)

	// A reload changes both routing and predicted silence; paged rows must still
	// match the standard endpoint and preserve duplicate route receivers.
	cfg, err = config.Load("route:\n  receiver: new\n  routes:\n  - receiver: new\n    continue: true\n  - receiver: new\nreceivers:\n- name: new\n")
	require.NoError(t, err)
	api.Update(cfg, func(ctx context.Context, ls labelset.LabelSet) {
		m, _ := marker.FromContext(ctx)
		m.SetSilenced(ls.Fingerprint(), []string{"silence-id"})
	})
	legacy = request("/api/v2/alerts")
	require.Equal(t, 200, legacy.Code, legacy.Body.String())
	require.NoError(t, json.Unmarshal(legacy.Body.Bytes(), &native))
	reloaded := get("column=fingerprint&order=asc&perPage=100&receiver=new")
	require.Equal(t, native, reloaded.Records)
	require.Contains(t, string(reloaded.Records[0]), "silence-id")
	require.Equal(t, 0, get("silenced=false").Total)
	require.Equal(t, 5, get("active=false").Total)
	var row struct {
		Receivers []json.RawMessage `json:"receivers"`
	}
	require.NoError(t, json.Unmarshal(reloaded.Records[0], &row))
	require.Len(t, row.Receivers, 2)
	expired := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "expired"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(-time.Minute)}, now, false)
	require.NoError(t, alerts.Put(t.Context(), expired))
	require.Equal(t, 5, get("").Total)
}

type blockedPageProvider struct {
	provider.Alerts
	entered chan struct{}
	ch      chan *provider.Alert
}

func (p *blockedPageProvider) GetPending() provider.AlertIterator {
	close(p.entered)
	return provider.NewAlertIterator(p.ch, make(chan struct{}), nil)
}

func TestOscarPageCancellationAndReload(t *testing.T) {
	p := &blockedPageProvider{entered: make(chan struct{}), ch: make(chan *provider.Alert)}
	api, err := NewAPI(p, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	status := func(context.Context, labelset.LabelSet) {}
	api.Update(cfg, status)
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/oscar/alerts/page", nil).WithContext(ctx))
	}()
	<-p.entered
	updated := make(chan struct{})
	go func() { api.Update(cfg, status); close(updated) }()
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("reload blocked by page traversal")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("page ignored cancellation")
	}
}

func TestOscarPageSortColumns(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	cfg, err := config.Load("route:\n  receiver: default\nreceivers:\n- name: default\n")
	require.NoError(t, err)
	api.Update(cfg, func(ctx context.Context, ls labelset.LabelSet) {
		m, _ := marker.FromContext(ctx)
		if ls.LabelSet["instance"] == "b" {
			m.SetSilenced(ls.Fingerprint(), []string{"silenced"})
		} else {
			m.SetSilenced(ls.Fingerprint(), nil)
		}
	})
	base := time.Now().UTC().Truncate(time.Millisecond)
	type row struct {
		id, name, severity, summary string
		start, end                  time.Time
		fp                          string
	}
	rows := []row{
		{id: "a", name: "Zebra", severity: "Warning", summary: "Alpha", start: base.Add(2 * time.Millisecond), end: base.Add(3 * time.Hour)},
		{id: "b", name: "alpha", severity: "critical", summary: "zulu", start: base.Add(3 * time.Millisecond), end: base.Add(time.Hour)},
		{id: "c", name: "ALPHA", severity: "", summary: "", start: time.Time{}, end: base.Add(2 * time.Hour)},
		{id: "d", name: "beta", severity: "Critical", summary: "ALPHA", start: base.Add(4 * time.Millisecond), end: base.Add(4 * time.Hour)},
		{id: "e", name: "beta", severity: "warning", summary: "beta", start: base.Add(5 * time.Millisecond), end: base.Add(5 * time.Hour)},
		{id: "f", name: "Beta", severity: "warning", summary: "beta", start: base.Add(5 * time.Millisecond), end: base.Add(5 * time.Hour)},
	}
	// Make the later sub-millisecond instant have the smaller fingerprint, so
	// an implementation comparing nanoseconds instead of milliseconds fails.
	for i := range rows {
		ls := model.LabelSet{"alertname": model.LabelValue(rows[i].name), "instance": model.LabelValue(rows[i].id)}
		if rows[i].severity != "" {
			ls["severity"] = model.LabelValue(rows[i].severity)
		}
		rows[i].fp = ls.Fingerprint().String()
	}
	if rows[4].fp < rows[5].fp {
		rows[4].start = rows[4].start.Add(500 * time.Microsecond)
	} else {
		rows[5].start = rows[5].start.Add(500 * time.Microsecond)
	}
	for _, r := range rows {
		ls := model.LabelSet{"alertname": model.LabelValue(r.name), "instance": model.LabelValue(r.id)}
		if r.severity != "" {
			ls["severity"] = model.LabelValue(r.severity)
		}
		annotations := model.LabelSet{}
		if r.summary != "" {
			annotations["summary"] = model.LabelValue(r.summary)
		}
		require.NoError(t, alerts.Put(t.Context(), alert.New(model.Alert{Labels: ls, Annotations: annotations, StartsAt: r.start, EndsAt: r.end}, base, false)))
	}
	columns := []string{"startsAt", "starts_at", "ends_at", "alertname", "severity", "instance", "summary", "alert_status", "fingerprint"}
	for _, column := range columns {
		for _, order := range []string{"asc", "desc"} {
			t.Run(column+"/"+order, func(t *testing.T) {
				expected := slices.Clone(rows)
				key := func(r row) string {
					switch column {
					case "startsAt", "starts_at":
						return r.start.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z07:00")
					case "ends_at":
						return r.end.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z07:00")
					case "alertname":
						return strings.ToLower(r.name)
					case "severity":
						return strings.ToLower(r.severity)
					case "instance":
						return r.id
					case "summary":
						return strings.ToLower(r.summary)
					case "alert_status":
						if r.id == "b" {
							return "suppressed"
						}
						return "active"
					default:
						return r.fp
					}
				}
				slices.SortFunc(expected, func(a, b row) int {
					c := strings.Compare(key(a), key(b))
					if c == 0 {
						c = strings.Compare(a.fp, b.fp)
					}
					if order == "desc" {
						return -c
					}
					return c
				})
				var actual []string
				for page := 1; page <= 2; page++ {
					w := httptest.NewRecorder()
					api.Handler.ServeHTTP(w, httptest.NewRequest("GET", fmt.Sprintf("/api/v2/oscar/alerts/page?column=%s&order=%s&page=%d&perPage=3", column, order, page), nil))
					require.Equal(t, 200, w.Code, w.Body.String())
					var result struct {
						Records []struct {
							Fingerprint string `json:"fingerprint"`
						} `json:"records"`
						Total int `json:"total_records"`
					}
					require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
					require.Equal(t, len(rows), result.Total)
					for _, r := range result.Records {
						actual = append(actual, r.Fingerprint)
					}
				}
				want := make([]string, 0, len(expected))
				for _, r := range expected {
					want = append(want, r.fp)
				}
				require.Equal(t, want, actual)
			})
		}
	}
}

func TestLegacyAlertsReloadKeepsRouteAndStatusTogether(t *testing.T) {
	alerts, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(alerts.Close)
	api, err := NewAPI(alerts, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	now := time.Now()
	for _, severity := range []string{"critical", "warning"} {
		require.NoError(t, alerts.Put(t.Context(), alert.New(model.Alert{Labels: model.LabelSet{"alertname": "Test", "severity": model.LabelValue(severity)}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)))
	}
	cfg := func(name string, inhibited bool) *config.Config {
		yaml := fmt.Sprintf("route:\n  receiver: %s\nreceivers:\n- name: %s\n", name, name)
		if inhibited {
			yaml += "inhibit_rules:\n- source_matchers: ['severity=\"critical\"']\n  target_matchers: ['severity=\"warning\"']\n  equal: [alertname]\n"
		}
		c, e := config.Load(yaml)
		require.NoError(t, e)
		return c
	}
	oldCfg, newCfg := cfg("old", true), cfg("new", false)
	makeInhibitor := func(c *config.Config) *inhibit.Inhibitor {
		i := inhibit.NewInhibitor(alerts, c.InhibitRules, promslog.NewNopLogger(), eventrecorder.NopRecorder())
		go i.Run()
		i.WaitForLoading()
		t.Cleanup(i.Stop)
		return i
	}
	oldInhibitor, newInhibitor := makeInhibitor(oldCfg), makeInhibitor(newCfg)
	api.Update(oldCfg, func(ctx context.Context, ls labelset.LabelSet) { oldInhibitor.Mutes(ctx, ls) })
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	api.beforeAlertsConfigLock = func() { entered <- struct{}{}; <-release }
	type response struct {
		query string
		w     *httptest.ResponseRecorder
	}
	responses := make(chan response, 2)
	for _, query := range []string{"", "?inhibited=false"} {
		go func() {
			w := httptest.NewRecorder()
			api.Handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v2/alerts"+query, nil))
			responses <- response{query: query, w: w}
		}()
	}
	<-entered
	<-entered
	api.Update(newCfg, func(ctx context.Context, ls labelset.LabelSet) { newInhibitor.Mutes(ctx, ls) })
	close(release)
	for range 2 {
		result := <-responses
		require.Equal(t, 200, result.w.Code, result.w.Body.String())
		var rows []struct {
			Labels    map[string]string `json:"labels"`
			Receivers []struct {
				Name string `json:"name"`
			} `json:"receivers"`
			Status struct {
				State       string   `json:"state"`
				InhibitedBy []string `json:"inhibitedBy"`
			} `json:"status"`
		}
		require.NoError(t, json.Unmarshal(result.w.Body.Bytes(), &rows))
		require.Len(t, rows, 2, result.query)
		for _, row := range rows {
			require.Equal(t, "new", row.Receivers[0].Name)
			require.Equal(t, "active", row.Status.State, row.Labels)
			require.Empty(t, row.Status.InhibitedBy)
		}
	}
}
