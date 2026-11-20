// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package v2

import (
	"context"
	"encoding/json"
	"net/http/httptest"
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
	api := API{
		alerts: p, logger: promslog.NewNopLogger(), m: metrics.NewAlerts(prometheus.NewRegistry()),
		alertmanagerConfig: &config.Config{Global: &config.GlobalConfig{ResolveTimeout: model.Duration(2 * time.Minute)}},
	}
	original := &models.PostableAlert{
		Alert:       models.Alert{Labels: models.LabelSet{"alertname": "A", "host": "h"}},
		Annotations: models.LabelSet{conversionAnnotation: `{"claims":{"producer":"webhookreceiver"}}`, "summary": "owned"},
		StartsAt:    strfmt.DateTime(now.Add(-time.Minute)),
	}
	request := httptest.NewRequest("POST", "/api/v2/alerts", nil)
	request = request.WithContext(context.WithValue(request.Context(), conversionActorKey{}, "webhookreceiver"))
	first := httptest.NewRecorder()
	api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: request, Alerts: models.PostableAlerts{original}}).WriteResponse(first, runtime.TextProducer())
	require.Equal(t, 200, first.Code, first.Body.String())
	stored, err := p.Get(model.LabelSet{"alertname": "A", "host": "h"}.Fingerprint())
	require.NoError(t, err)
	wire, err := json.Marshal(AlertToOpenAPIAlert(stored, alert.AlertStatus{State: alert.AlertStateActive}, nil, nil))
	require.NoError(t, err)
	var gettable models.GettableAlert
	require.NoError(t, json.Unmarshal(wire, &gettable))
	require.Equal(t, stored.StartsAt.UTC().Format(time.RFC3339Nano), gettable.StartsAtRaw)
	require.NotEmpty(t, gettable.Annotations["__oscar_fingerprint_conversion_resolution"])
	var ending models.PostableAlert
	require.NoError(t, json.Unmarshal(wire, &ending))
	ending.EndsAt = strfmt.DateTime(now.Add(-time.Millisecond))
	request = request.WithContext(context.WithValue(request.Context(), conversionActorKey{}, "alertmanager-resolution"))
	response := httptest.NewRecorder()
	api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: request, Alerts: models.PostableAlerts{&ending}}).WriteResponse(response, runtime.TextProducer())
	require.Equal(t, 200, response.Code, response.Body.String())
}
