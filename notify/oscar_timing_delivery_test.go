// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package notify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
)

func TestFailedFirstAndRepeatDeliveryDoNotAdvanceNativeTimingBaseline(t *testing.T) {
	reg := prometheus.NewRegistry()
	log, err := nflog.New(nflog.Options{Retention: 3 * time.Hour, Metrics: reg})
	require.NoError(t, err)
	recv := &nflogpb.Receiver{GroupName: "team", Integration: "webhook", Idx: 0}
	a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown"}, EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	hash := HashAlert(a)
	stage := func() MultiStage {
		integration := NewIntegration(notifierFunc(func(context.Context, ...*alert.Alert) NotifyVerdict {
			return Unrecoverable(errors.New("delivery failed"), DefaultReason)
		}), sendResolved(true), "webhook", 0, "team")
		return MultiStage{
			NewDedupStage(&integration, log, recv),
			NewRetryStage(integration, "team", NewMetrics(prometheus.NewRegistry(), featurecontrol.NoopFlags{}), eventrecorder.NopRecorder()),
			NewSetNotifiesStage(log, recv, featurecontrol.NoopFlags{}),
		}
	}
	ctx := WithRepeatInterval(WithGroupKey(context.Background(), "group"), time.Nanosecond)
	_, _, err = stage().Exec(ctx, promslog.NewNopLogger(), a)
	require.Error(t, err)
	first := log.LookupTiming("group", recv, []uint64{hash}, 1)
	require.False(t, first.Found, "failed first send must not create a baseline")

	require.NoError(t, log.Log(recv, "group", []uint64{hash}, nil, nil, nil, time.Hour))
	baseline := log.LookupTiming("group", recv, []uint64{hash}, 1)
	require.True(t, baseline.Found)
	require.True(t, baseline.Firing[hash])
	_, _, err = stage().Exec(ctx, promslog.NewNopLogger(), a)
	require.Error(t, err)
	after := log.LookupTiming("group", recv, []uint64{hash}, 1)
	require.Equal(t, baseline.Timestamp, after.Timestamp, "failed repeat must preserve previous baseline")
}
