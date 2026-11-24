// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/notify"
)

// errRetryBackoff holds a deferred resolved member so the dispatcher keeps it.
var errRetryBackoff = errors.New("NATIVE_RETRY_BACKOFF")

const (
	ledgerMaxEntries = 100_000
	backoffBase      = 30 * time.Second
	backoffCap       = 5 * time.Minute
)

// ledgerKey names one alert at one native target of one aggregation group.
// The group key pins the route, and so the target's repeat interval.
type ledgerKey struct {
	group, receiver, integration string
	index                        int
	source                       model.Fingerprint
}

// ledgerSnap is everything OSCAR's due check depends on, plus the outgoing
// labels and whether the member is terminal on either side.
type ledgerSnap struct {
	ref                 v2.EpisodeRef
	severity, lifecycle uint64
	labels              model.Fingerprint
	terminal            bool
}

type ledgerEntry struct {
	covered      ledgerSnap
	nextEligible time.Time // zero: no provable ordinary coverage
	failed       ledgerSnap
	attempts     int
	nextAttempt  time.Time
}

// deliveryLedger remembers, per alert and native target, the ordinary
// coverage OSCAR is proven to hold, and the alert's retry backoff.
//
// It only removes calls whose answer is provably "covered": a deadline comes
// from this process's own confirmed settle (taken before the settle was sent,
// so it falls due no later than OSCAR's next_eligible) or from a deadline
// OSCAR returned and the lease clock maps conservatively. Any difference in
// epoch, episode, revision, lifecycle, labels or terminal state falls through
// to OSCAR. A backoff applies only while the member is unchanged.
type deliveryLedger struct {
	mu      sync.Mutex
	epoch   uint64
	entries map[ledgerKey]*ledgerEntry
	now     func() time.Time
}

func newDeliveryLedger() *deliveryLedger {
	return &deliveryLedger{entries: make(map[ledgerKey]*ledgerEntry), now: time.Now}
}

func ledgerKeyFor(ctx context.Context, receiver, integration string, index int, m *alert.Alert) ledgerKey {
	group, _ := notify.GroupKey(ctx)
	return ledgerKey{group: group, receiver: receiver, integration: integration, index: index, source: m.ProviderSource().Fingerprint()}
}

func snapOf(p v2.EpisodeProjection, m *alert.Alert, now time.Time) ledgerSnap {
	s := m.ProviderSource()
	terminal := p.State != "firing" || m.ResolvedAt(now) || s.ResolvedAt(now) || s.ManagedOperationKind == "clear"
	return ledgerSnap{ref: p.EpisodeRef, severity: p.SeverityRevision, lifecycle: p.LifecycleSeq, labels: m.Labels.Fingerprint(), terminal: terminal}
}

func (a *nativeActions) ledgerEpoch() uint64 {
	if a.recovery == nil {
		return 0
	}
	epoch, _ := a.recovery.RecoveryState()
	return epoch
}

func (l *deliveryLedger) clock() time.Time {
	if l == nil {
		return time.Now()
	}
	return l.now()
}

// Caller holds l.mu. A lease epoch change discards every entry.
func (l *deliveryLedger) lockedAt(epoch uint64) {
	if epoch != l.epoch {
		clear(l.entries)
		l.epoch = epoch
	}
}

// covered reports whether OSCAR would answer "covered" for this member.
func (l *deliveryLedger) covered(k ledgerKey, epoch uint64, s ledgerSnap) bool {
	if l == nil || s.terminal {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedAt(epoch)
	e := l.entries[k]
	return e != nil && e.covered == s && l.now().Before(e.nextEligible)
}

// deferred reports whether this unchanged member is still inside its backoff.
func (l *deliveryLedger) deferred(k ledgerKey, epoch uint64, s ledgerSnap) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedAt(epoch)
	e := l.entries[k]
	if e == nil || e.attempts == 0 {
		return false
	}
	if e.failed != s { // new, changed or resolved since the failure: contact now
		e.attempts, e.nextAttempt = 0, time.Time{}
		return false
	}
	return l.now().Before(e.nextAttempt)
}

// cover records proven coverage until a local deadline and clears any backoff.
// A terminal member forgets its entry.
func (l *deliveryLedger) cover(k ledgerKey, epoch uint64, s ledgerSnap, until time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedAt(epoch)
	if s.terminal {
		delete(l.entries, k)
		return
	}
	*l.lockedEntry(k) = ledgerEntry{covered: s, nextEligible: until}
}

// settled clears the backoff after OSCAR answered covered (keep) or completed (forget).
func (l *deliveryLedger) settled(k ledgerKey, epoch uint64, forget bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedAt(epoch)
	if forget {
		delete(l.entries, k)
	} else if e := l.entries[k]; e != nil {
		e.attempts, e.nextAttempt = 0, time.Time{}
	}
}

// fail starts or extends the member's backoff from the flush start: 30 s, 1 m, 2 m, 4 m, then 5 m.
func (l *deliveryLedger) fail(k ledgerKey, epoch uint64, s ledgerSnap, at time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lockedAt(epoch)
	e := l.lockedEntry(k)
	if e.failed != s {
		e.attempts = 0
	}
	delay := backoffCap
	if e.attempts < 4 {
		delay = backoffBase << e.attempts
	}
	e.failed, e.attempts, e.nextAttempt = s, e.attempts+1, at.Add(delay)
}

// Caller holds l.mu.
func (l *deliveryLedger) lockedEntry(k ledgerKey) *ledgerEntry {
	if e := l.entries[k]; e != nil {
		return e
	}
	if len(l.entries) >= ledgerMaxEntries {
		now := l.now()
		for key, e := range l.entries {
			if !now.Before(e.nextEligible) && !now.Before(e.nextAttempt) {
				delete(l.entries, key)
			}
		}
		// ponytail: arbitrary eviction when still full. Safe: the alert falls back to asking OSCAR.
		for key := range l.entries {
			if len(l.entries) < ledgerMaxEntries {
				break
			}
			delete(l.entries, key)
		}
	}
	e := &ledgerEntry{}
	l.entries[k] = e
	return e
}
