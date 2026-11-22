// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"container/list"
	"context"
	"sync/atomic"
	"time"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
)

// A resident follows one provider-owned pointer. The list is also the fair
// recovery cursor. No historical rows or unbounded dirty-event queue are kept.
type actionResident struct {
	claim                               *atomic.Bool
	direct                              *v2.DirectContact
	key                                 string
	source, routed                      *alert.Alert
	routedGeneration                    uint64
	order, revision, epoch, recordEpoch uint64
	unknown                             bool
	retry                               time.Time
	place                               *list.Element
}

func residentKey(owner string, s *alert.Alert) string {
	if owner != "" {
		return "m/" + owner
	}
	return "n/" + s.Fingerprint().String()
}

// DirectContact returns the unresolved local entry for this resident key.
func (a *nativeActions) DirectContact(key string) *v2.DirectContact {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if r := a.residents[key]; r != nil {
		return r.direct
	}
	return nil
}

// ChangeDirectContact transfers exact local ownership under the provider gate.
func (a *nativeActions) ChangeDirectContact(key string, old, next *v2.DirectContact) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.residents[key]
	if r == nil || r.direct != old {
		return false
	}
	r.direct = next
	return true
}

// PublicationGeneration pins journal work to its originating graph.
func (a *nativeActions) PublicationGeneration() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.generation
}

// VerifiedNegative certifies the exact pointer classified in this epoch.
func (a *nativeActions) VerifiedNegative(s *alert.Alert, epoch uint64) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	g := a.graph
	if g == nil || g.epoch != epoch || !a.currentLocked(g, s) {
		return false
	}
	_, tracked := a.sources[s.Fingerprint()]
	return !tracked
}

// PublishedEpisode certifies the current projection for eligibility and local actions.
func (a *nativeActions) PublishedEpisode(s *alert.Alert, p v2.EpisodeProjection) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.graph == nil || !a.currentLocked(a.graph, s) {
		return false
	}
	prior, ok := a.sources[s.Fingerprint()]
	return ok && prior.p.EpisodeRef == p.EpisodeRef && prior.p.SeverityRevision == p.SeverityRevision && prior.p.LifecycleSeq == p.LifecycleSeq
}

func (a *nativeActions) publishedFiring(g *actionGraph, s *alert.Alert) *v2.EpisodeProjection {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.currentLocked(g, s) {
		return nil
	}
	old, ok := a.sources[s.Fingerprint()]
	if !ok || old.member.ProviderSource() != s || old.p.State != "firing" {
		return nil
	}
	p := old.p
	return &p
}

// FreezeEpisode issues a witness to this exact resident publication, including
// projections restored directly from the index without a mutable episode slot.
func (a *nativeActions) FreezeEpisode(s *alert.Alert, p v2.EpisodeProjection) *atomic.Bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.graph
	if g == nil || !a.currentLocked(g, s) {
		return nil
	}
	old, ok := a.sources[s.Fingerprint()]
	if !ok || old.member.ProviderSource() != s || old.p.EpisodeRef != p.EpisodeRef || old.p.SeverityRevision != p.SeverityRevision || old.p.LifecycleSeq != p.LifecycleSeq {
		return nil
	}
	r := a.residents[residentKey(s.ManagedMember.Episode, s)]
	if r.claim == nil {
		r.claim = new(atomic.Bool)
		r.claim.Store(true)
	}
	return r.claim
}

func (r *actionResident) invalidateClaim() {
	if r.claim != nil {
		r.claim.Store(false)
		r.claim = nil
	}
}

func (a *nativeActions) forgetLocked(source *alert.Alert) {
	fp := source.Fingerprint()
	if old, ok := a.sources[fp]; ok && old.member.ProviderSource() == source {
		delete(a.sources, fp)
		delete(a.episodes, old.p.EpisodeRef.EpisodeID)
	}
}

func (a *nativeActions) uncertainLocked(r *actionResident) {
	r.invalidateClaim()
	r.unknown = true
	r.revision++
	if g := a.graph; g != nil {
		g.inhibitor.UpdateProjection(r.source.Fingerprint(), nil)
		g.inhibitor.UpdateUnresolved(r.source.Fingerprint(), r.source)
	}
}

// Queue overflow retains each resident's uncertainty and starts another
// bounded cursor pass. An unrelated alert can enter during that pass.
func (g *actionGraph) enqueue(r *actionResident) {
	if g.queued == nil {
		g.queued = make(map[*actionResident]*list.Element)
	}
	if g.queued[r] != nil {
		return
	}
	if len(g.queued) >= 256 {
		g.rescan = true
		return
	}
	g.queued[r] = g.dirty.PushBack(r)
}

// InvalidateSource holds this resident and its possible dependents before a floor write.
func (a *nativeActions) InvalidateSource(source *alert.Alert) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r := a.residents[residentKey(source.ManagedMember.Episode, source)]; r != nil && r.source == source {
		a.uncertainLocked(r)
		if a.graph != nil {
			a.graph.enqueue(r)
		}
	}
}

// ObserveSource invalidates resident projections synchronously with provider mutation.
func (a *nativeActions) ObserveSource(owner string, source *alert.Alert, closed, possible bool) (*alert.Alert, *v2.DirectContact) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := residentKey(owner, source)
	r := a.residents[key]
	var previous *alert.Alert
	if r != nil {
		previous = r.source
		if closed && source != nil && source != previous {
			return previous, nil
		}
		r.invalidateClaim()
		a.forgetLocked(previous)
		if g := a.graph; g != nil {
			g.inhibitor.UpdateUnresolved(previous.Fingerprint(), nil)
			g.inhibitor.UpdateProjection(previous.Fingerprint(), nil)
		}
	}
	if closed {
		if r != nil {
			if g := a.graph; g != nil && r.routed != nil && r.routedGeneration == g.generation {
				select {
				case g.retired <- r.routed:
				default:
					g.sweepRetired.Store(true)
				}
			}
			if g := a.graph; g != nil {
				if g.cursor == r.place {
					g.cursor = r.place.Next()
				}
				if e := g.queued[r]; e != nil {
					g.dirty.Remove(e)
					delete(g.queued, r)
				}
			}
			a.order.Remove(r.place)
			delete(a.residents, key)
			return previous, r.direct
		}
		return previous, nil
	}
	if r == nil {
		a.sequence++
		r = &actionResident{key: key, order: a.sequence}
		r.place = a.order.PushBack(r)
		a.residents[key] = r
	}
	r.source = source
	r.revision++
	r.unknown = possible
	if g := a.graph; g != nil {
		r.epoch = g.epoch
		if possible {
			r.retry = time.Time{}
			g.enqueue(r)
			g.inhibitor.UpdateUnresolved(source.Fingerprint(), source)
		} else {
			g.inhibitor.UpdateProjection(source.Fingerprint(), source)
		}
	}
	return previous, nil
}

func (a *nativeActions) retired(g *actionGraph, member *alert.Alert) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s := member.ProviderSource()
	r := a.residents[residentKey(s.ManagedMember.Episode, s)]
	return a.graph == g && (r == nil || r.source != s)
}

// graphView is used by each subscription with its originating graph. Its use
// callback only updates that graph's local caches.
func (a *nativeActions) graphView(g *actionGraph, s *alert.Alert, routing bool, use func(*alert.Alert)) {
	if a.recovery == nil {
		a.readView(s, use)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.graph != g {
		return
	}
	r := a.residents[residentKey(s.ManagedMember.Episode, s)]
	if r == nil || r.source != s || r.unknown || r.epoch != g.epoch {
		return
	}
	member := s
	if p, ok := a.sources[s.Fingerprint()]; ok && p.member.ProviderSource() == s {
		if !routing && p.p.State == "resolved" {
			use(nil)
			return
		}
		member = p.member
	}
	if routing {
		if old := r.routed; old != nil && r.routedGeneration == g.generation && old != member {
			g.dispatcher.ReplaceProjection(g.ctx, old, member)
		} else {
			use(member)
		}
		r.routed, r.routedGeneration = member, g.generation
	} else {
		use(member)
	}
}

func (a *nativeActions) currentLocked(g *actionGraph, s *alert.Alert) bool {
	if a.graph != g {
		return false
	}
	if a.recovery == nil {
		return true
	}
	epoch, _ := a.recovery.RecoveryState()
	r := a.residents[residentKey(s.ManagedMember.Episode, s)]
	return g.published && epoch != 0 && g.epoch == epoch && r != nil && r.source == s && !r.unknown && r.epoch == epoch
}

func (g *actionGraph) checkViews(ctx context.Context, source *alert.Alert, views []*alert.Alert) bool {
	if g.adapter == nil {
		return true
	}
	a := g.adapter
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.currentLocked(g, source) {
		p, retrying := v2.RetryFloorProjection(ctx, source)
		if !retrying || a.graph != g || a.recovery == nil {
			return false
		}
		epoch, _ := a.recovery.RecoveryState()
		r := a.residents[residentKey(source.ManagedMember.Episode, source)]
		base, ok := a.sources[source.Fingerprint()]
		if !g.published || epoch == 0 || g.epoch != epoch || r == nil || r.source != source || r.epoch != epoch || !ok ||
			base.p.EpisodeRef != p.EpisodeRef || base.p.SeverityRevision != p.SeverityRevision || base.p.LifecycleSeq != p.LifecycleSeq {
			return false
		}
	}
	for _, m := range views {
		if g.inhibitor.MayDependOnUnresolved(m.Labels, source.Fingerprint()) {
			return false
		}
	}
	return true
}

func (a *nativeActions) installed(g *actionGraph) {
	a.mu.Lock()
	g.generation = a.generation
	a.graph = g
	a.mu.Unlock()
	if a.recovery != nil {
		go a.recoverGraph(g)
	}
}

func (a *nativeActions) recoverGraph(g *actionGraph) {
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case old := <-g.retired:
			a.mu.RLock()
			s := old.ProviderSource()
			r := a.residents[residentKey(s.ManagedMember.Episode, s)]
			if a.graph == g && (r == nil || r.source != s) {
				g.dispatcher.RetireProjection(old)
			}
			a.mu.RUnlock()
			continue
		case <-t.C:
		}
		for range 64 {
			if !a.recoverOne(g) {
				break
			}
		}
	}
}

func (a *nativeActions) recoverOne(g *actionGraph) bool {
	epoch, _ := a.recovery.RecoveryState()
	if epoch == 0 {
		return false
	}
	a.mu.Lock()
	if a.graph != g {
		a.mu.Unlock()
		return false
	}
	if g.epoch != epoch {
		g.epoch, g.published, g.scanning, g.cutoff, g.cursor = epoch, false, true, a.sequence, a.order.Front()
	}
	var r *actionResident
	if g.scanning {
		if g.cursor == nil || g.cursor.Value.(*actionResident).order > g.cutoff {
			g.published, g.scanning = true, false
			a.mu.Unlock()
			return false
		}
		r = g.cursor.Value.(*actionResident)
		g.cursor = g.cursor.Next()
	} else if e := g.dirty.Front(); e != nil && !time.Now().Before(e.Value.(*actionResident).retry) {
		r = e.Value.(*actionResident)
		g.dirty.Remove(e)
		delete(g.queued, r)
	} else if g.rescan {
		g.scanning, g.rescan, g.cutoff, g.cursor = true, false, a.sequence, a.order.Front()
		a.mu.Unlock()
		return false
	} else {
		a.mu.Unlock()
		return false
	}
	source := r.source
	if r.epoch == epoch && !r.unknown && r.routedGeneration == g.generation {
		a.mu.Unlock()
		return true
	}
	if !g.published {
		revision := r.revision
		a.mu.Unlock()
		possible := a.recovery.MayHaveEpisode(epoch, source)
		a.mu.Lock()
		defer a.mu.Unlock()
		live, _ := a.recovery.RecoveryState()
		if live != epoch || a.graph != g || a.residents[r.key] != r || r.revision != revision {
			return true
		}
		if possible {
			a.uncertainLocked(r)
			r.epoch = epoch
			g.enqueue(r)
		} else {
			a.installMemberLocked(g, r, nil, source)
		}
		return true
	}
	a.uncertainLocked(r)
	revision := r.revision
	a.mu.Unlock()
	p, err := a.recovery.ClassifyResident(g.ctx, epoch, source)
	a.mu.Lock()
	defer a.mu.Unlock()
	live, _ := a.recovery.RecoveryState()
	if live != epoch || a.graph != g || a.residents[r.key] != r || r.revision != revision {
		return true
	}
	if err != nil {
		r.retry = time.Now().Add(time.Second)
		g.enqueue(r)
		return true
	}
	var member *alert.Alert
	if p != nil {
		member, err = effectiveMember(source, *p)
		if err != nil {
			r.retry = time.Now().Add(time.Second)
			g.enqueue(r)
			return true
		}
	} else {
		member = source
	}
	a.installMemberLocked(g, r, p, member)
	return true
}

func (a *nativeActions) installMemberLocked(g *actionGraph, r *actionResident, p *v2.EpisodeProjection, member *alert.Alert) bool {
	if old, ok := a.sources[r.source.Fingerprint()]; ok && old.member.ProviderSource() == r.source && r.recordEpoch == g.epoch {
		if p == nil || old.p.EpisodeRef.EpisodeID != p.EpisodeRef.EpisodeID || old.p.EpisodeRef.Generation > p.EpisodeRef.Generation ||
			old.p.EpisodeRef.Generation == p.EpisodeRef.Generation && (old.p.EpisodeRef.VariantRevision > p.EpisodeRef.VariantRevision ||
				old.p.LifecycleSeq > p.LifecycleSeq || old.p.SeverityRevision > p.SeverityRevision ||
				old.p.SeverityRevision == p.SeverityRevision && old.p.Floor != p.Floor || old.p.LifecycleSeq == p.LifecycleSeq && old.p.State != p.State ||
				old.p.State == "resolved" && p.State != "resolved") {
			a.uncertainLocked(r)
			r.retry = time.Now().Add(time.Second)
			g.enqueue(r)
			return false
		}
	}
	r.invalidateClaim()
	a.forgetLocked(r.source)
	if e := g.queued[r]; e != nil {
		g.dirty.Remove(e)
		delete(g.queued, r)
	}
	if p != nil {
		pub := publishedMember{*p, member}
		a.sources[r.source.Fingerprint()] = pub
		a.episodes[p.EpisodeRef.EpisodeID] = pub
		r.recordEpoch = g.epoch
	}
	g.inhibitor.UpdateUnresolved(r.source.Fingerprint(), nil)
	if p != nil && p.State == "resolved" {
		g.inhibitor.UpdateProjection(r.source.Fingerprint(), nil)
	} else {
		g.inhibitor.UpdateProjection(r.source.Fingerprint(), member)
	}
	old := r.routed
	if old == nil || r.routedGeneration != g.generation {
		old = r.source
	}
	g.dispatcher.ReplaceProjection(g.ctx, old, member)
	r.routed, r.routedGeneration, r.unknown, r.epoch = member, g.generation, false, g.epoch
	r.revision++
	return true
}

// A journal turn pins the graph and epoch before any blocking work. The
// provider observer owns the pointer map, so checking it and installing its view
// are a single local transition; no provider mutex is acquired here.
func (a *nativeActions) publishResident(ctx context.Context, p v2.EpisodeProjection, source *alert.Alert) error {
	epoch, gen := v2.PublicationToken(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.graph
	live, _ := a.recovery.RecoveryState()
	if g == nil || live == 0 || live != epoch || g.epoch != epoch || gen != a.generation {
		return actionHeld
	}
	if source == nil {
		// An observed removal already retired the resident. A tombstone from
		// an older variant cannot remove a replacement.
		return nil
	}
	r := a.residents[residentKey(source.ManagedMember.Episode, source)]
	if r == nil || r.source != source {
		return actionHeld
	}
	if old, ok := a.sources[source.Fingerprint()]; ok && old.member.ProviderSource() == source {
		if old.p.EpisodeRef == p.EpisodeRef && old.p.SeverityRevision == p.SeverityRevision && old.p.Floor == p.Floor && old.p.State == p.State && old.p.LifecycleSeq == p.LifecycleSeq && !r.unknown && r.routedGeneration == g.generation && r.epoch == epoch {
			return nil
		}
		if old.p.EpisodeRef.Generation > p.EpisodeRef.Generation || old.p.EpisodeRef == p.EpisodeRef && (old.p.LifecycleSeq > p.LifecycleSeq || old.p.SeverityRevision > p.SeverityRevision) {
			return actionHeld
		}
	}
	member, err := effectiveMember(source, p)
	if err != nil {
		return err
	}
	if !a.installMemberLocked(g, r, &p, member) {
		return actionHeld
	}
	return nil
}

func (g *actionGraph) callbackCommissioned() bool {
	if g.adapter == nil || g.adapter.recovery == nil {
		return true
	}
	_, receipts := g.adapter.recovery.RecoveryState()
	return receipts && g.supported
}

type entryTransition struct {
	ctx       context.Context
	deadline  time.Time
	witnesses []func() bool
}

func (f *entryTransition) limit(t time.Time) {
	if !t.IsZero() && (f.deadline.IsZero() || t.Before(f.deadline)) {
		f.deadline = t
	}
}

// finalPublication runs after blocking destination/claim checks. The successful
// local entry and dependency check share the provider observer's publication lock.
func (a *nativeActions) finalPublication(g *actionGraph, members []*alert.Alert, contacts []ordinaryContact, active map[*alert.Alert]bool, fence entryTransition, enter func()) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var signed, legacy, cohortIssued bool
	for i, m := range members {
		if !active[m] {
			continue
		}
		s, c := m.ProviderSource(), contacts[i]
		cohortIssued = cohortIssued || c.admission != nil
		if !a.currentLocked(g, s) {
			return false
		}
		if c.legacy {
			if _, tracked := a.sources[s.Fingerprint()]; c.pass == nil || tracked {
				return false
			}
		}
		if c.contact.integration.canonical {
			signed = signed || !c.legacy
			legacy = legacy || c.legacy
		}
		if a.recovery != nil && c.pass == nil {
			pub, ok := a.sources[s.Fingerprint()]
			if !ok || pub.member.ProviderSource() != s || pub.p.EpisodeRef != c.p.EpisodeRef || pub.p.LifecycleSeq != c.p.LifecycleSeq || pub.p.SeverityRevision != c.p.SeverityRevision {
				return false
			}
		}
		views := []*alert.Alert{s, m}
		if c.p.PreviousEffective != "" && c.p.PreviousEffective != c.p.EffectiveSeverity() {
			view, err := alert.BuildDispatchView(s, c.p.EpisodeRef, c.p.PreviousEffective, c.p.SeverityRevision)
			if err != nil {
				return false
			}
			views = append(views, view.NotificationMember())
		}
		for _, v := range views {
			if g.inhibitor.MayDependOnUnresolved(v.Labels, s.Fingerprint()) || g.inhibitor.HasInhibitor(v.Labels, s.Fingerprint()) {
				return false
			}
		}
	}
	for _, valid := range fence.witnesses {
		if !valid() {
			return false
		}
	}
	if a.recovery != nil {
		epoch, receipts := a.recovery.RecoveryState()
		if epoch == 0 || epoch != g.epoch || signed && !(receipts && g.supported) || legacy && receipts && g.supported {
			return false
		}
	} else if legacy {
		return false
	}
	if cohortIssued && !a.journal.(v2.OrdinaryCohortJournal).CohortSupported() {
		return false
	}
	if fence.ctx.Err() != nil || !fence.deadline.IsZero() && !time.Now().Before(fence.deadline) {
		return false
	}
	enter()
	return true
}
