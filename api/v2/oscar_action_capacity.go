// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"container/list"
	"context"
	"sync/atomic"
	"time"

	"github.com/prometheus/alertmanager/alert"
)

// A detached claim keeps an immutable witness to the same resident through
// cache churn. A new observation or floor invalidates every such claim.
type parkedEpisode struct {
	source *alert.Alert
	stamp  *atomic.Bool
}

type observationHandoff struct {
	version  uint64
	base     *alert.Alert
	events   []actionEvent
	overflow bool
	removed  bool
	work     *list.Element
}

func (o *nativeActionOwner) slotLocked(key string, create bool) *episodeSlot {
	s := o.byKey[key]
	if s != nil || !create || len(o.byKey) >= o.maxEpisodes || o.directHeldLocked(key) {
		return s
	}
	bucket, bit := membershipBit(key)
	possible := o.membership[bucket]&bit != 0
	o.membership[bucket] |= bit
	o.enrollments++
	s = &episodeSlot{needsRestore: (o.deferredRecovery || o.readSource != nil) && possible}
	parked, wasParked := o.parked[key]
	if wasParked {
		s.source, s.stamp, s.needsRestore = parked.source, parked.stamp, true
		delete(o.parked, key)
	}
	if hand := o.handoffs[key]; hand != nil {
		s.source = hand.base
		s.pending = hand.events
		if len(s.pending) > 0 {
			s.source = s.pending[len(s.pending)-1].source
		}
		s.removed, s.overflow, s.needsRestore = hand.removed, hand.overflow, true
		o.work.Remove(hand.work)
		delete(o.handoffs, key)
	}
	// A collision in the lost-edge summary must be checked against the
	// indexed durable source before creating a new identity.
	if !wasParked && o.gaps[bucket]&bit != 0 {
		s.needsRestore = true
		s.checkGap = true
	}
	s.clock = o.clock.PushBack(key)
	o.byKey[key] = s
	return s
}

func (o *nativeActionOwner) evictOne() bool {
	o.mu.Lock()
	n := o.clock.Len()
	o.mu.Unlock()
	for range n {
		o.mu.Lock()
		e := o.clock.Front()
		if e == nil {
			o.mu.Unlock()
			return false
		}
		o.clock.MoveToBack(e)
		key := e.Value.(string)
		s := o.byKey[key]
		o.mu.Unlock()
		if s == nil || !s.turn.TryLock() {
			continue
		}
		o.mu.Lock()
		s.local.Lock()
		idle := o.byKey[key] == s && !s.detached && !s.removed && !s.overflow && !s.ambiguous && len(s.pending) == 0 && s.source != nil && s.projection.ID != "" && !s.needsRestore && !s.needsPublish && !s.uncertain && s.next == nil && s.floorWrite == nil && !o.directHeldLocked(key)
		if idle {
			o.parked[key] = parkedEpisode{s.source, s.stamp}
			o.unlinkLocked(key, s)
			o.deferredRecovery = true
		}
		s.local.Unlock()
		o.mu.Unlock()
		s.turn.Unlock()
		if idle {
			return true
		}
	}
	return false
}

// Call outside the provider turn. At saturation, bound both waiting callers
// and their wait, serializing reclamation through the FIFO channel waiter queue.
// While hand-offs are at their bound, only an enrollment that absorbs one may
// reclaim; others fail fast and retry, so queued edges drain first.
func (o *nativeActionOwner) obtainSlot(ctx context.Context, key string, try func() (*episodeSlot, error)) (*episodeSlot, error) {
	if s, err := try(); s != nil || err != nil {
		return s, err
	}
	o.mu.Lock()
	held := o.directHeldLocked(key)
	backPressure := len(o.handoffs) >= o.maxHandoffs && o.handoffs[key] == nil
	o.mu.Unlock()
	if held {
		return nil, reconcile
	}
	if backPressure {
		o.metrics.handoffBackpressure()
		return nil, unavailable
	}
	select {
	case o.waiters <- struct{}{}:
		defer func() { <-o.waiters }()
	default:
		return nil, unavailable
	}
	timer := time.NewTimer(125 * time.Millisecond)
	defer timer.Stop()
	select {
	case o.admitter <- struct{}{}:
		defer func() { <-o.admitter }()
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, unavailable
	}
	for {
		if s, err := try(); s != nil || err != nil {
			return s, err
		}
		if o.evictOne() {
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, unavailable
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Caller holds the key map and slot local locks (and the episode turn).
func (o *nativeActionOwner) unlinkLocked(key string, s *episodeSlot) {
	s.detached = true
	delete(o.byKey, key)
	if s.clock != nil {
		o.clock.Remove(s.clock)
		s.clock = nil
	}
	if id := s.projection.EpisodeRef.EpisodeID; o.byID[id] == s {
		delete(o.byID, id)
	}
}

func (s *episodeSlot) invalidateLocked() {
	if s.stamp != nil {
		s.stamp.Store(false)
		s.stamp = nil
	}
}

// bufferLocked preserves observed lifecycle edges across mutable-slot eviction.
// A lost intermediate edge (transition overflow) latches conservative key
// membership; absence alone cannot repair it.
func (o *nativeActionOwner) bufferLocked(key string, previous, source *alert.Alert, removed bool) {
	bucket, bit := membershipBit(key)
	park, parked := o.parked[key]
	if parked {
		if previous == nil {
			previous = park.source
		}
		if park.stamp != nil {
			park.stamp.Store(false)
		}
	}
	if source == nil {
		source = previous
	}
	if source == nil || removed && previous != nil && source != previous {
		return
	}
	h := o.handoffs[key]
	if h == nil {
		if !parked && (previous == nil && !removed || o.recovered && o.membership[bucket]&bit == 0 && o.terminalMembership[bucket]&bit == 0) {
			return
		}
		// Never discard an edge at capacity: at most one hand-off per key, and
		// obtainSlot applies back-pressure past maxHandoffs.
		h = &observationHandoff{base: previous, work: o.work.PushBack(key)}
		o.handoffs[key] = h
	}
	delete(o.parked, key)
	h.version++
	h.removed = removed
	if h.overflow {
		return
	}
	appendEvent := func(event actionEvent) {
		if n := len(h.events); n > 1 && sameVariant(variantOf(h.events[n-1].source), variantOf(event.source)) && h.events[n-1].source.ManagedMember == event.source.ManagedMember && h.events[n-1].closed == event.closed {
			h.events[n-1] = event
		} else if n < maxTransitions {
			h.events = append(h.events, event)
		} else {
			h.overflow = true
			o.metrics.handoffOverflow()
			o.gaps[bucket] |= bit
		}
	}
	if previous != nil && !previous.ManagedReceiver && !previous.StartsAt.Equal(source.StartsAt) && previous.Resolved() && !previous.EndsAt.After(source.StartsAt) {
		appendEvent(actionEvent{previous, true})
	}
	appendEvent(actionEvent{source, removed || source.Resolved() || source.ManagedOperationKind == "clear"})
}

// drainHandoff probes only the affected key, even when no notification is due.
// Keep its queued edges until either indexed absence or a serialized slot owns them.
func (o *nativeActionOwner) drainHandoff(ctx context.Context) bool {
	o.mu.Lock()
	e := o.work.Front()
	if e == nil {
		o.mu.Unlock()
		return false
	}
	o.work.MoveToBack(e)
	key := e.Value.(string)
	h := o.handoffs[key]
	first := h.base
	if first == nil && len(h.events) > 0 {
		first = h.events[0].source
	}
	bucket, bit := membershipBit(key)
	if h.overflow || o.gaps[bucket]&bit != 0 {
		o.work.Remove(e)
		delete(o.handoffs, key)
		o.mu.Unlock()
		return true
	}
	version := h.version
	candidate := o.membership[bucket]&bit != 0
	o.mu.Unlock()
	if first == nil {
		return true
	}
	var p *EpisodeProjection
	if candidate {
		rows, err := o.sourceRows(ctx, first.ActionOwner(), first.Fingerprint().String())
		if err != nil {
			return true
		}
		if len(rows) > 0 {
			p = &rows[0]
		}
	}
	if p == nil {
		var err error
		p, err = o.terminalCandidate(ctx, first)
		if err != nil {
			return true
		}
	}
	if !o.live(ctx) {
		return true
	}
	if p == nil {
		o.mu.Lock()
		if o.handoffs[key] == h && h.version == version {
			o.work.Remove(e)
			delete(o.handoffs, key)
		}
		o.mu.Unlock()
		return true
	}
	s, err := o.obtainSlot(ctx, key, func() (*episodeSlot, error) {
		o.mu.Lock()
		defer o.mu.Unlock()
		epoch, _ := PublicationToken(ctx)
		if o.handoffs[key] != h || !o.lease.currentEpoch(epoch) {
			return nil, reconcile
		}
		return o.slotLocked(key, true), nil
	})
	if err != nil {
		return true
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	s.local.Lock()
	ok := !s.detached && !s.overflow && !s.ambiguous
	s.local.Unlock()
	if !ok {
		return true
	}
	if s.projection.ID == "" {
		if err := o.restoreIndexed(ctx, s, *p, first); err != nil {
			return true
		}
	}
	o.sweepSlot(ctx, key, s)
	return true
}

// DirectContact is an opaque resident-owned pre-enrollment entry. Only its
// issuing owner may release it with conclusive provider evidence.
type DirectContact struct{ detached, overflow bool }

func (o *nativeActionOwner) directHeldLocked(key string) bool {
	bucket, _ := membershipBit(key)
	if o.untracked[key] != 0 || o.directOverflow[bucket] != 0 {
		return true
	}
	if pub, ok := o.dispatch.(ActionPublication); ok {
		return pub.DirectContact(key) != nil
	}
	return false
}

func (o *nativeActionOwner) detachDirectLocked(key string, contact *DirectContact) {
	contact.detached = true
	if len(o.untracked) < o.maxEpisodes {
		o.untracked[key] = 1
		return
	}
	// No unresolved source is forgotten when every exact detached position
	// is occupied. Collisions hold only this bucket. A saturated counter
	// stays held, since its actual multiplicity is no longer known.
	bucket, _ := membershipBit(key)
	contact.overflow = true
	if o.directOverflow[bucket] != ^uint32(0) {
		o.directOverflow[bucket]++
	}
}

func (o *nativeActionOwner) finishDirectLocked(key string, contact *DirectContact) {
	if contact.overflow {
		bucket, _ := membershipBit(key)
		n := o.directOverflow[bucket]
		if n > 0 && n != ^uint32(0) {
			o.directOverflow[bucket]--
		}
	} else if pub, ok := o.dispatch.(ActionPublication); ok && !contact.detached {
		pub.ChangeDirectContact(key, contact, nil)
	} else {
		delete(o.untracked, key)
	}
}
