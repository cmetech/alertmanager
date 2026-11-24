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

// ledgerTarget is one alert at one receiver integration. OSCAR keeps one
// coverage row per such target key (its key ignores the repeat interval and
// full-receiver scope), so every aggregation group sharing it is invalidated
// together when any contact on it is confirmed.
type ledgerTarget struct {
	receiver, integration string
	index                 int
	source                model.Fingerprint
}

// ledgerKey adds the aggregation group, which pins the route and its repeat interval.
type ledgerKey struct {
	target ledgerTarget
	group  string
}

// ledgerSnap is everything OSCAR's due check depends on, plus the outgoing
// labels and whether the member is terminal on either side.
type ledgerSnap struct {
	ref                 v2.EpisodeRef
	severity, lifecycle uint64
	labels              model.Fingerprint
	terminal, wire      bool // wire: resolved on the wire or at the source, or a managed clear
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
// OSCAR returned on a covered row, mapped conservatively by the lease clock.
// Any confirmed contact on the target (ordinary or explicit, any scope) first
// drops every entry for it, because it can lower OSCAR's deadline. Any
// difference in epoch, episode, revision, lifecycle, labels or terminal state
// falls through to OSCAR. A backoff applies only while the member is unchanged.
type deliveryLedger struct {
	mu      sync.Mutex
	epoch   uint64
	size    int
	version uint64                  // bumped by every invalidation, epoch change or lapse
	floor   uint64                  // stamps below it are stale for every target
	stamps  map[ledgerTarget]uint64 // version of each target's last invalidation
	entries map[ledgerTarget]map[string]*ledgerEntry
	now     func() time.Time
	metrics *ledgerMetrics
}

func newDeliveryLedger() *deliveryLedger {
	return &deliveryLedger{entries: make(map[ledgerTarget]map[string]*ledgerEntry), stamps: make(map[ledgerTarget]uint64), now: time.Now}
}

func ledgerKeyFor(ctx context.Context, receiver, integration string, index int, m *alert.Alert) ledgerKey {
	group, _ := notify.GroupKey(ctx)
	return ledgerKey{target: ledgerTarget{receiver: receiver, integration: integration, index: index, source: m.ProviderSource().Fingerprint()}, group: group}
}

func snapOf(p v2.EpisodeProjection, m *alert.Alert, now time.Time) ledgerSnap {
	s := m.ProviderSource()
	wire := m.ResolvedAt(now) || s.ResolvedAt(now) || s.ManagedOperationKind == "clear"
	return ledgerSnap{ref: p.EpisodeRef, severity: p.SeverityRevision, lifecycle: p.LifecycleSeq, labels: m.Labels.Fingerprint(), terminal: p.State != "firing" || wire, wire: wire}
}

// ledgerLapsed marks a lapsed lease: nothing is decided or recorded, and the
// ledger is kept for a renewal of the same epoch (a new epoch clears it).
const ledgerLapsed = ^uint64(0)

func (a *nativeActions) ledgerEpoch() uint64 {
	if a.recovery == nil {
		return 0
	}
	epoch, _ := a.recovery.RecoveryState()
	if epoch == 0 {
		return ledgerLapsed
	}
	return epoch
}

func (l *deliveryLedger) clock() time.Time {
	if l == nil {
		return time.Now()
	}
	return l.now()
}

// Caller holds l.mu. A lease epoch change discards every entry; a lapsed
// lease decides and records nothing (false).
func (l *deliveryLedger) lockedAt(epoch uint64) bool {
	if epoch == ledgerLapsed {
		l.lockedStaleAll() // a deadline read before the lapse is not recorded after it
		return false
	}
	if epoch != l.epoch {
		l.metrics.invalidated("lease", l.size)
		clear(l.entries)
		l.epoch, l.size = epoch, 0
		l.lockedStaleAll()
	}
	return true
}

// Caller holds l.mu.
func (l *deliveryLedger) lockedStaleAll() {
	l.version++
	l.floor = l.version
	clear(l.stamps)
}

// decide classifies one member before any call: "skip" (OSCAR would answer
// covered), "defer" (inside its backoff) or "contact", with the reason.
// Skips are allowed only for unprepared integrations.
func (l *deliveryLedger) decide(k ledgerKey, epoch uint64, s ledgerSnap, allowSkip bool) (decision, reason string) {
	defer func() { l.metrics.decided(decision, reason) }()
	if l == nil {
		return "contact", "fallback"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lockedAt(epoch) {
		return "contact", "fallback"
	}
	now := l.now()
	e := l.lockedGet(k)
	switch {
	case e != nil && e.attempts > 0 && e.failed == s && now.Before(e.nextAttempt):
		return "defer", "backoff"
	case s.terminal:
		return "contact", "resolved"
	case e == nil:
		return "contact", "new"
	case e.attempts > 0:
		return "contact", "retry"
	case !allowSkip || e.nextEligible.IsZero():
		return "contact", "fallback"
	case e.covered != s:
		if e.covered.ref != s.ref || e.covered.severity != s.severity || e.covered.lifecycle != s.lifecycle {
			l.metrics.invalidated("revision", 1)
		}
		return "contact", "changed"
	case now.Before(e.nextEligible):
		return "skip", "covered"
	}
	return "contact", "due"
}

// stamp returns the invalidation version; take it before the call whose
// result cover will record.
func (l *deliveryLedger) stamp() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.version
}

// Caller holds l.mu.
func (l *deliveryLedger) lockedGet(k ledgerKey) *ledgerEntry {
	return l.entries[k.target][k.group]
}

// covered reports whether OSCAR would answer "covered" for this member.
func (l *deliveryLedger) covered(k ledgerKey, epoch uint64, s ledgerSnap) bool {
	if l == nil || s.terminal {
		return false
	}
	decision, _ := l.decide(k, epoch, s, true)
	return decision == "skip"
}

// deferred reports whether this unchanged member is still inside its backoff.
func (l *deliveryLedger) deferred(k ledgerKey, epoch uint64, s ledgerSnap) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lockedAt(epoch) {
		return false
	}
	e := l.lockedGet(k)
	// A member that is new, changed or resolved since the failure is contacted
	// now; its next failure restarts the schedule (see fail).
	return e != nil && e.attempts > 0 && e.failed == s && l.now().Before(e.nextAttempt)
}

// invalidate drops every entry for a target after any confirmed contact on it.
func (l *deliveryLedger) invalidate(t ledgerTarget, epoch uint64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.lockedAt(epoch)
	l.metrics.invalidated("confirmed_contact", len(l.entries[t]))
	l.size -= len(l.entries[t])
	delete(l.entries, t)
	l.version++
	if len(l.stamps) >= ledgerMaxEntries {
		// ponytail: bound the stamp map by making every older stamp stale at once.
		clear(l.stamps)
		l.floor = l.version
	}
	l.stamps[t] = l.version
}

// cover records proven coverage until a local deadline and clears any backoff.
// A terminal member forgets its entry. The deadline is dropped if its target
// was invalidated after since (a concurrent confirm may have lowered it).
func (l *deliveryLedger) cover(k ledgerKey, epoch uint64, s ledgerSnap, until time.Time, since uint64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lockedAt(epoch) {
		return
	}
	if s.terminal || since < l.floor || l.stamps[k.target] > since {
		l.lockedDelete(k)
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
	if !l.lockedAt(epoch) {
		return
	}
	if forget {
		l.lockedDelete(k)
	} else if e := l.lockedGet(k); e != nil {
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
	if !l.lockedAt(epoch) {
		return
	}
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
func (l *deliveryLedger) lockedDelete(k ledgerKey) {
	groups := l.entries[k.target]
	if _, ok := groups[k.group]; !ok {
		return
	}
	delete(groups, k.group)
	l.size--
	if len(groups) == 0 {
		delete(l.entries, k.target)
	}
}

// Caller holds l.mu.
func (l *deliveryLedger) lockedEntry(k ledgerKey) *ledgerEntry {
	if e := l.lockedGet(k); e != nil {
		return e
	}
	if l.size >= ledgerMaxEntries {
		now := l.now()
		for t, groups := range l.entries {
			for g, e := range groups {
				if !now.Before(e.nextEligible) && !now.Before(e.nextAttempt) {
					l.lockedDelete(ledgerKey{t, g})
				}
			}
		}
		// ponytail: arbitrary eviction when still full. Safe: the alert falls back to asking OSCAR.
		for t := range l.entries {
			if l.size < ledgerMaxEntries {
				break
			}
			l.size -= len(l.entries[t])
			delete(l.entries, t)
		}
	}
	groups := l.entries[k.target]
	if groups == nil {
		groups = make(map[string]*ledgerEntry)
		l.entries[k.target] = groups
	}
	e := &ledgerEntry{}
	groups[k.group] = e
	l.size++
	return e
}
