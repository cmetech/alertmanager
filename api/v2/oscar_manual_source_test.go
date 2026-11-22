// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestManualSourceKeepsOriginalStartAndChecksPredecessor(t *testing.T) {
	const authority = "64171238-3cc5-448e-bd12-7502a062ec63"
	start := time.Now().UTC().Truncate(time.Millisecond)
	makeWork := func(work string, position int64, severity string) manualPublication {
		raw := model.Alert{Labels: model.LabelSet{"severity": model.LabelValue(severity)}, StartsAt: start, EndsAt: start.Add(time.Hour)}
		return manualPublication{OwnerID: strings.Repeat("d", 64), SourceEpisodeID: strings.Repeat("e", 64), SourceGeneration: 1, Position: position,
			Locator: manualLocator{Work: strings.Repeat(work, 64)}, Stamp: strings.Repeat(work, 64), NativeUUID: "41bec59a-0517-4803-b45e-9fdc8bb83874",
			Payload: raw, Fingerprint: raw.Labels.Fingerprint().String()}
	}
	first := makeWork("a", 1, "major")
	initial, err := first.update(authority, nil)
	require.NoError(t, err)
	first.Projection = EpisodeProjection{episodeUpdate: initial, Floor: "critical", SeverityRevision: 2}
	later := makeWork("b", 2, "warning")
	later.Predecessor = &first.Locator
	next, err := later.update(authority, &first)
	require.NoError(t, err)
	require.Equal(t, initial.EpisodeRef.EpisodeID, next.EpisodeRef.EpisodeID)
	require.Equal(t, initial.ActiveSince, next.ActiveSince)
	require.Equal(t, initial.EpisodeRef.VariantRevision+1, next.EpisodeRef.VariantRevision)
	require.Nil(t, next.ManagedOwner)
	renew := makeWork("c", 2, "major")
	renew.Predecessor = &first.Locator
	same, err := renew.update(authority, &first)
	require.NoError(t, err)
	require.Equal(t, initial.EpisodeRef, same.EpisodeRef)
	require.Equal(t, initial.LifecycleSeq+1, same.LifecycleSeq)
	renew.Terminal = true
	terminal, err := renew.update(authority, &first)
	require.NoError(t, err)
	require.Equal(t, "resolved", terminal.State)
	for _, change := range []func(*manualPublication){
		func(m *manualPublication) { m.Position++ }, func(m *manualPublication) { m.SourceGeneration++ },
		func(m *manualPublication) { m.Predecessor = &manualLocator{Work: strings.Repeat("f", 64)} },
		func(m *manualPublication) { m.Fingerprint = "1" }, func(m *manualPublication) { m.Payload.StartsAt = m.Payload.StartsAt.Add(time.Nanosecond) },
	} {
		bad := later
		change(&bad)
		_, err = bad.update(authority, &first)
		require.Error(t, err)
	}
}
