// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package mem

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/provider"
)

func TestOscarActionManagedReplacementObservesCommittedMemberOnly(t *testing.T) {
	t.Parallel()
	p := clearProvider(t, &clearCallback{})
	p.EnableManaged()
	var seen []*alert.Alert
	p.SetActionObserver(func(_ string, a *alert.Alert, _ bool) { seen = append(seen, a) })
	for i := 1; i <= 2; i++ {
		a := managedFixture(i, "problem")
		require.NoError(t, p.ApplyManaged(t.Context(), "owner", a, provider.ManagedStamp{Generation: int64(i)}, func() error { return nil }))
	}
	require.Len(t, seen, 2)
	require.True(t, seen[1].ManagedReceiver)
	require.NotEqual(t, seen[0].Fingerprint(), seen[1].Fingerprint())
	require.NoError(t, p.ApplyManaged(t.Context(), "owner", nil, provider.ManagedStamp{Generation: 3}, func() error { return nil }))
	require.Nil(t, seen[2])
}
