// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package v2

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/api/metrics"
	models "github.com/prometheus/alertmanager/api/v2/models"
	alertops "github.com/prometheus/alertmanager/api/v2/restapi/operations/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestConversionResolutionActualGETPOSTCodec(t *testing.T) {
	t.Parallel()
	now := time.Now()
	p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	require.NoError(t, err)
	api := API{alerts: p, logger: promslog.NewNopLogger(), m: metrics.NewAlerts(prometheus.NewRegistry()),
		alertmanagerConfig: &config.Config{Global: &config.GlobalConfig{ResolveTimeout: model.Duration(2 * time.Minute)}}}
	original := &models.PostableAlert{Alert: models.Alert{Labels: models.LabelSet{"alertname": "A", "host": "h"}},
		Annotations: models.LabelSet{conversionAnnotation: `{"claims":{"producer":"webhookreceiver"}}`, "summary": "owned"},
		StartsAt:    strfmt.DateTime(now.Add(-time.Minute))}
	request := httptest.NewRequest("POST", "/api/v2/alerts", nil)
	request = request.WithContext(context.WithValue(request.Context(), conversionActorKey{}, "webhookreceiver"))
	first := httptest.NewRecorder()
	api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: request, Alerts: models.PostableAlerts{original}}).WriteResponse(first, runtime.TextProducer())
	require.Equal(t, 200, first.Code, first.Body.String())
	stored, err := p.Get(model.LabelSet{"alertname": "A", "host": "h"}.Fingerprint())
	require.NoError(t, err)
	wire, err := json.Marshal(AlertToOpenAPIAlert(stored, alert.AlertStatus{State: alert.AlertStateActive}, nil, nil))
	require.NoError(t, err)
	var ending models.PostableAlert
	require.NoError(t, json.Unmarshal(wire, &ending))
	ending.EndsAt = strfmt.DateTime(now.Add(-time.Millisecond))
	request = request.WithContext(context.WithValue(request.Context(), conversionActorKey{}, "alertmanager-resolution"))
	response := httptest.NewRecorder()
	api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: request, Alerts: models.PostableAlerts{&ending}}).WriteResponse(response, runtime.TextProducer())
	require.Equal(t, 200, response.Code, response.Body.String())
}

func TestManagedPublicationStopsAtOwnerBoundary(t *testing.T) {
	var vectors struct{ Valid map[string]any }
	wire, err := os.ReadFile("testdata/managed_operation_v1.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(wire, &vectors))
	now := time.Now().Unix()
	vectors.Valid["issued_at"] = now
	vectors.Valid["deadline"] = now + 10
	encoded, err := json.Marshal(vectors.Valid)
	require.NoError(t, err)
	labels := models.LabelSet{"alertname": "fixture", "node": "node", "alert_type": "resolution", "is_resolution": "true", "correlation_key": vectors.Valid["correlation"].(string)}
	start, err := time.Parse(time.RFC3339Nano, vectors.Valid["clear_at"].(string))
	require.NoError(t, err)
	post := &models.PostableAlert{Alert: models.Alert{Labels: labels}, Annotations: models.LabelSet{managedAnnotation: string(encoded)}, StartsAt: strfmt.DateTime(start)}
	p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), nil, nil)
	require.NoError(t, err)
	api := API{alerts: p, logger: promslog.NewNopLogger(), m: metrics.NewAlerts(prometheus.NewRegistry()), alertmanagerConfig: &config.Config{Global: &config.GlobalConfig{ResolveTimeout: model.Duration(time.Minute)}}}
	key := bytes.Repeat([]byte("s"), 32)
	guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var posts models.PostableAlerts
		require.NoError(t, json.NewDecoder(r.Body).Decode(&posts))
		api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: r, Alerts: posts}).WriteResponse(w, runtime.TextProducer())
	}), map[string][]byte{"smtpreceiver/v1": key})
	request := func(signed bool) *httptest.ResponseRecorder {
		body, e := json.Marshal(models.PostableAlerts{post})
		require.NoError(t, e)
		r := httptest.NewRequest(http.MethodPost, "/api/v2/alerts", bytes.NewReader(body))
		if signed {
			r = conversionRequest(body, "smtpreceiver", key)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		return w
	}
	require.Equal(t, 503, request(true).Code)
	fp := APILabelSetToModelLabelSet(labels).Fingerprint()
	_, err = p.Get(fp)
	require.Error(t, err)
	post.Annotations[conversionAnnotation] = "unowned"
	require.Equal(t, 400, request(true).Code)
	delete(post.Annotations, conversionAnnotation)
	post.StartsAt = strfmt.DateTime(start.Add(time.Millisecond))
	require.Equal(t, 400, request(true).Code)
	labels[managedAnnotation] = "untrusted"
	require.Equal(t, 200, request(false).Code)
	stored, err := p.Get(fp)
	require.NoError(t, err)
	require.NotContains(t, stored.Labels, model.LabelName(managedAnnotation))
	require.NotContains(t, stored.Annotations, model.LabelName(managedAnnotation))
}
