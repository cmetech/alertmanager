// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// scanFixture serves the operation scan from fixed rows and counts native-actions calls.
type scanFixture struct {
	mu      sync.Mutex
	rows    []ActionResultV1
	pages   int
	lookups map[string]int
	claims  int
	now     time.Time
	last    map[string]time.Time
	gap     time.Duration // shortest interval between two recoveries of one operation
}

func newScanFixture(n int, state string) *scanFixture {
	f := &scanFixture{lookups: map[string]int{}, last: map[string]time.Time{}, gap: time.Hour}
	for i := range n {
		f.rows = append(f.rows, ActionResultV1{
			OperationID: fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1),
			State:       "unknown",
			EpisodeRef:  EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-2222-4222-8222-222222222222", Generation: 1, VariantRevision: 1},
			Targets:     []TargetResult{{TargetKey: "a", State: state}},
		})
	}
	return f
}

func (f *scanFixture) call(_ context.Context, cmd string, p map[string]any, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case cmd == "recover" && p["projection"] == "operations":
		f.pages++
		after, _ := p["after_id"].(string)
		page := []ActionResultV1{}
		for _, r := range f.rows {
			if r.OperationID > after && len(page) < 32 {
				page = append(page, r)
			}
		}
		b, _ := json.Marshal(page)
		return json.Unmarshal(b, out)
	case cmd == "lookup" && p["projection"] == "intent":
		// One call stands for the three a real recovery makes; nil ends recoverWork.
		id := p["operation_id"].(string)
		f.lookups[id]++
		if prev, ok := f.last[id]; ok && f.now.Sub(prev) < f.gap {
			f.gap = f.now.Sub(prev)
		}
		f.last[id] = f.now
		return nil
	case cmd == "claim-manual-source":
		f.claims++
		return nil
	}
	return unavailable
}

func (f *scanFixture) owner() (*nativeActionOwner, context.Context) {
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(f.call), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Hour)}
	o.recovered = true
	return o, context.WithValue(context.Background(), actionEpochKey{}, uint64(1))
}

func (f *scanFixture) recoveries() int {
	total := 0
	for _, n := range f.lookups {
		total += n
	}
	return total
}

// tick runs one maintain tick of the scan and fails if it read more than one page.
func (f *scanFixture) tick(turn context.Context, o *nativeActionOwner, scan *operationScan, at time.Time) {
	f.mu.Lock()
	f.now = at
	pages := f.pages
	f.mu.Unlock()
	o.scanOperations(turn, turn, scan, at)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pages > pages+1 {
		panic("scanOperations read more than one page in a tick")
	}
}

// AC-1: unchanged rows cost at most 1 + 3N/B requests per second over ten minutes,
// counting pages, the boot page and lease renewals, with three calls per recovery.
func TestOscarActionScanBacksOffUnchangedOperations(t *testing.T) {
	t.Parallel()
	for _, n := range []int{1, 32, 100, 640} {
		f := newScanFixture(n, "unknown")
		o, turn := f.owner()
		scan := &operationScan{}
		start := time.Now()
		const window = 600
		for s := range window {
			f.tick(turn, o, scan, start.Add(time.Duration(s)*time.Second))
		}
		renewals, boot := window/10, 1
		requests := float64(f.pages + boot + renewals + 3*f.recoveries())
		bound := (1 + 3*float64(n)/operationBackoff.Seconds()) * window
		require.LessOrEqual(t, requests, bound, "N=%d pages=%d recoveries=%d", n, f.pages, f.recoveries())
		require.Greater(t, f.gap, operationBackoff, "N=%d", n)
		for _, r := range f.rows {
			period := max(int(operationBackoff.Seconds())+1, (n+31)/32+1) // a pass reads one page per tick
			require.GreaterOrEqual(t, f.lookups[r.OperationID], window/period-1, "every operation is still recovered")
		}
	}
}

// AC-2: a row that appears or changes between passes is recovered on the next pass,
// which starts on the first tick B plus one tick after the previous pass started.
func TestOscarActionScanRecoversChangedRowsOnTheNextPass(t *testing.T) {
	t.Parallel()
	f := newScanFixture(2, "unknown")
	late := f.rows[1]
	f.rows = f.rows[:1]
	o, turn := f.owner()
	scan := &operationScan{}
	start := time.Now()
	at := func(s int) time.Time { return start.Add(time.Duration(s) * time.Second) }
	for s := range 5 {
		f.tick(turn, o, scan, at(s))
	}
	f.mu.Lock()
	f.rows = append(f.rows, late)
	f.rows[0].Targets = []TargetResult{{TargetKey: "a", State: "confirmed"}}
	f.mu.Unlock()
	for s := 5; s < 17; s++ {
		f.tick(turn, o, scan, at(s))
	}
	require.Equal(t, 0, f.lookups[late.OperationID], "passes stay B plus one tick apart")
	require.Equal(t, 1, f.lookups[f.rows[0].OperationID])
	f.tick(turn, o, scan, at(17))
	require.Equal(t, 1, f.lookups[late.OperationID])
	require.Equal(t, 2, f.lookups[f.rows[0].OperationID])
}

// AC-3: pending or held work is recovered at least every B plus one tick, and a fresh
// scan (owner restart) recovers it at once.
func TestOscarActionScanBoundsPendingAndHeldRecovery(t *testing.T) {
	t.Parallel()
	for _, held := range []bool{false, true} {
		f := newScanFixture(1, "pending")
		if held {
			f.rows[0].State, f.rows[0].Targets = "held", []TargetResult{}
		}
		o, turn := f.owner()
		scan := &operationScan{}
		start := time.Now()
		for s := range 60 {
			f.tick(turn, o, scan, start.Add(time.Duration(s)*time.Second))
		}
		id := f.rows[0].OperationID
		require.Equal(t, 4, f.lookups[id]) // t = 0, 17, 34, 51
		restarted := &operationScan{}
		f.tick(turn, o, restarted, start.Add(60*time.Second))
		require.Equal(t, 5, f.lookups[id])
	}
}

// AC-2/AC-3: tick jitter does not push a pass one tick past B plus one tick.
func TestOscarActionScanPassSpacingToleratesTickJitter(t *testing.T) {
	t.Parallel()
	f := newScanFixture(1, "unknown")
	o, turn := f.owner()
	scan := &operationScan{}
	start := time.Now()
	f.tick(turn, o, scan, start.Add(600*time.Millisecond)) // the pass starts late in its tick
	for k := 1; k <= 17; k++ {
		f.tick(turn, o, scan, start.Add(time.Duration(k)*time.Second+100*time.Millisecond))
	}
	require.Equal(t, 2, f.lookups[f.rows[0].OperationID], "the pass due at tick 17 runs at tick 17")
}

type idleManual struct{ manualProvider }

// AC-4: manual-source pulls keep their 1 s cadence while the operation scan backs off.
func TestOscarActionMaintainKeepsManualCadenceWhileScanBacksOff(t *testing.T) {
	t.Parallel()
	f := newScanFixture(4, "unknown")
	o, _ := f.owner()
	o.lease.ManualSourceBridge, o.lease.ManualSourceDue = 1, true
	o.manual = idleManual{}
	ctx, cancel := context.WithTimeout(t.Context(), 4500*time.Millisecond)
	defer cancel()
	o.maintain(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.GreaterOrEqual(t, f.claims, 3)
	require.Equal(t, 2, f.pages, "one page and its empty end, then the scan waits")
	for _, r := range f.rows {
		require.Equal(t, 1, f.lookups[r.OperationID])
	}
}
