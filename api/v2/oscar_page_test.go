// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package v2

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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
	require.JSONEq(t, `{"records":[],"total_records":0,"total_pages":0}`, w.Body.String())
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
	all := append(append(asc.Records, middle.Records...), last.Records...)
	require.Equal(t, native, all)
	desc := get("column=startsAt&order=desc&perPage=100")
	slices.Reverse(all)
	require.Equal(t, all, desc.Records)
	require.Equal(t, 5, get("severity=CRITICAL&receiver=default&receiver_matchers=owner%3D%22team%22").Total)
	require.Equal(t, 1, get("quick_search=STRASSE").Total)
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
