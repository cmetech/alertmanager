// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestCallbackProvenanceKeepsStructuralSiblingsAndRawSeverity(t *testing.T) {
	t.Parallel()
	root := dispatch.NewRoute(&config.Route{Receiver: "first", Routes: []*config.Route{
		{Receiver: "first", Continue: true}, {Receiver: "second"},
	}}, nil)
	first := actionIntegration{canonical: true, digest: "first-digest", callbackPath: alert.NativeCallbackPath}
	second := actionIntegration{canonical: true, digest: "second-digest", callbackPath: alert.NativeCallbackPath + "?notifier_type=oscaradmin"}
	g := actionGraph{graphID: "graph", routes: root, targets: map[string][]actionIntegration{"first": {first}, "second": {second, {digest: "direct"}}}}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "MaJoR"}}, time.Now(), false)
	proof := g.callbackProvenance(source, plannedContact{integration: first, route: root.Routes[0]})
	require.NotNil(t, proof)
	require.Equal(t, "MaJoR", *proof.SourceSeverity)
	require.Len(t, proof.Routes, 2)
	require.NotEqual(t, proof.Routes[0].Route, proof.Routes[1].Route)
	require.Equal(t, second.callbackPath, proof.Routes[1].Path)
	require.Nil(t, g.callbackProvenance(source, plannedContact{integration: actionIntegration{}}))
}
