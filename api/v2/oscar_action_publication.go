// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"context"
	"time"

	"github.com/prometheus/alertmanager/alert"
)

// ActionPublication receives only local invalidations during a provider turn.
// These methods must never acquire a provider/owner lock or perform I/O.
type ActionPublication interface {
	ObserveSource(string, *alert.Alert, bool, bool) (*alert.Alert, *DirectContact)
	DirectContact(string) *DirectContact
	ChangeDirectContact(string, *DirectContact, *DirectContact) bool
	InvalidateSource(*alert.Alert)
	PublicationGeneration() uint64
	VerifiedNegative(*alert.Alert, uint64) bool
	PublishedEpisode(*alert.Alert, EpisodeProjection) bool
}

// RecoveryJournal is the assembly's internal lease-scoped recovery interface.
// The epoch becomes usable after membership recovery, before public readiness.
type RecoveryJournal interface {
	RecoveryState() (epoch uint64, receipts bool)
	MayHaveEpisode(uint64, *alert.Alert) bool
	ClassifyResident(context.Context, uint64, *alert.Alert) (*EpisodeProjection, error)
}

type publicationGenerationKey struct{}

// PublicationToken identifies the owner and graph at the start of a journal turn.
func PublicationToken(ctx context.Context) (epoch, generation uint64) {
	epoch, _ = ctx.Value(actionEpochKey{}).(uint64)
	generation, _ = ctx.Value(publicationGenerationKey{}).(uint64)
	return
}

type recoveredLease struct {
	epoch    uint64
	deadline time.Time
	receipts bool
}

func (o *nativeActionOwner) publishLeaseLocked() {
	if !o.recovered {
		o.publicLease.Store(nil)
		return
	}
	o.publicLease.Store(&recoveredLease{o.lease.Epoch, o.lease.ExpiresAt, bytes.Equal(bytes.TrimSpace(o.lease.NativeDeliveryReceipts), []byte("1"))})
}

// RecoveryState is a local lock-free read, including when called under the
// projection lock during provider observation or final entry.
func (o *nativeActionOwner) RecoveryState() (uint64, bool) {
	l := o.publicLease.Load()
	if l == nil || !l.deadline.After(time.Now()) {
		return 0, false
	}
	return l.epoch, l.receipts
}

// MayHaveEpisode supplies local negative evidence only after both indexed
// membership scans are complete. Positive candidates still need exact proof.
func (o *nativeActionOwner) MayHaveEpisode(epoch uint64, s *alert.Alert) bool {
	key := sourceKey(s.ManagedMember.Episode, s.Fingerprint().String())
	bucket, bit := membershipBit(key)
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.recovered || !o.lease.currentEpoch(epoch) || o.byKey[key] != nil || o.handoffs[key] != nil ||
		o.membership[bucket]&bit != 0 || o.terminalMembership[bucket]&bit != 0 || o.gaps[bucket]&bit != 0
}

func (o *nativeActionOwner) sourceRows(ctx context.Context, owner, fp string) ([]EpisodeProjection, error) {
	var managed any
	if owner != "" {
		managed = owner
	}
	var rows []EpisodeProjection
	if err := o.read(ctx, "recover", map[string]any{"projection": "source", "fingerprint": fp, "managed_key": managed}, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 1 {
		return nil, reconcile
	}
	for _, row := range rows {
		k, err := o.projectionKey(row)
		if err != nil || k != owner || !managedUUID.MatchString(row.ID) || row.State != "firing" || owner == "" && row.NativeVariant.Fingerprint != fp {
			return nil, reconcile
		}
	}
	return rows, nil
}

func sameResident(p EpisodeProjection, a *alert.Alert) bool {
	if a == nil || !sameVariant(p.NativeVariant, variantOf(a)) || (p.ManagedOwner != nil) != a.ManagedReceiver {
		return false
	}
	if m := p.ManagedOwner; m != nil && (m.EpisodeKey != a.ManagedMember.Episode || m.Generation != a.ManagedMember.Generation) {
		return false
	}
	if p.State == "resolved" {
		return a.Resolved() || a.ManagedOperationKind == "clear"
	}
	return !a.Resolved() && a.ManagedOperationKind != "clear" && sourceSeverity(a, "firing") == p.SourceSeverity
}

// ClassifyResident never creates an episode. A clean restored read can publish
// without allocating mutable coordination state. Ambiguous identity stays held.
func (o *nativeActionOwner) ClassifyResident(ctx context.Context, epoch uint64, a *alert.Alert) (*EpisodeProjection, error) {
	ctx = o.withEpoch(context.WithValue(ctx, actionEpochKey{}, epoch))
	if !o.live(ctx) || a == nil {
		return nil, unavailable
	}
	fp, owner := a.Fingerprint().String(), a.ManagedMember.Episode
	key := sourceKey(owner, fp)
	bucket, bit := membershipBit(key)
	o.mu.Lock()
	s := o.byKey[key]
	hand := o.handoffs[key]
	candidate := o.membership[bucket]&bit != 0
	park, parked := o.parked[key]
	gap := o.gaps[bucket]&bit != 0 && !(parked && park.source == a)
	o.mu.Unlock()
	// A summary collision can require an indexed read. Definitive absence
	// remains sufficient for a new source; a surviving binding plus a lost
	// intermediate lifecycle edge needs independent reconciliation.

	if s != nil {
		s.turn.Lock()
		defer s.turn.Unlock()
		if s.latest() != a || s.projection.ID == "" && s.next == nil {
			return nil, reconcile
		}
		if err := o.flush(ctx, s); err != nil {
			return nil, err
		}
		p := s.projection
		if err := s.current(p, a, false); err != nil {
			return nil, err
		}
		if !sameResident(p, a) || s.floorWrite != nil || s.uncertain {
			return nil, reconcile
		}
		if err := o.verifySource(ctx, a, p.State); err != nil {
			return nil, err
		}
		return &p, nil
	}
	if hand != nil {
		return nil, reconcile
	}
	var p *EpisodeProjection
	if candidate || gap {
		rows, err := o.sourceRows(ctx, owner, fp)
		if err != nil {
			return nil, err
		}
		if len(rows) == 1 {
			p = &rows[0]
		}
	}
	if p == nil {
		var err error
		p, err = o.terminalCandidate(ctx, a)
		if err != nil {
			return nil, err
		}
	}
	if p != nil {
		if gap {
			return nil, reconcile
		}
		if !sameResident(*p, a) {
			// A current managed successor proves lineage through the managed
			// journal. An expired exact ordinary interval proves its own close.
			managed := a.ManagedReceiver && p.ManagedOwner != nil && p.ManagedOwner.EpisodeKey == owner && p.ManagedOwner.Generation < a.ManagedMember.Generation
			expired := sameVariant(p.NativeVariant, variantOf(a)) && a.Resolved() && !a.ManagedReceiver && p.ManagedOwner == nil
			if p.State != "firing" || (!managed && !expired) {
				return nil, reconcile
			}
			s, err := o.sourceSlot(ctx, a, false)
			if err != nil {
				return nil, err
			}
			s.turn.Lock()
			defer s.turn.Unlock()
			if !o.live(ctx) || s.latest() != a {
				return nil, reconcile
			}
			if s.projection.ID == "" {
				s.projection = *p
				s.needsRestore = false
				s.local.Lock()
				if len(s.pending) == 0 {
					s.observeLocked(owner, a, false)
				}
				s.local.Unlock()
			}
			if err = o.flush(ctx, s); err != nil {
				return nil, err
			}
			current := s.projection
			if !sameResident(current, a) {
				return nil, reconcile
			}
			if err = s.current(current, a, false); err != nil {
				return nil, err
			}
			p = &current
		}
		if err := o.verifySource(ctx, a, p.State); err != nil {
			return nil, err
		}
	}
	if !o.live(ctx) {
		return nil, unavailable
	}
	return p, nil
}

// Allocate and seed under the exact pointer gate, retrying capacity outside
// it. A replacement during the wait cannot inherit another source's enrollment.
func (o *nativeActionOwner) sourceSlot(ctx context.Context, a *alert.Alert, enroll bool) (*episodeSlot, error) {
	owner, fp := a.ManagedMember.Episode, a.Fingerprint().String()
	key := sourceKey(owner, fp)
	epoch, _ := PublicationToken(ctx)
	return o.obtainSlot(ctx, key, func() (*episodeSlot, error) {
		var s *episodeSlot
		var result error = unverified
		o.readSource(owner, fp, func(current *alert.Alert) {
			if current != a {
				return
			}
			o.mu.Lock()
			defer o.mu.Unlock()
			if !o.recovered || !o.lease.currentEpoch(epoch) {
				result = unavailable
				return
			}
			if o.directHeldLocked(key) {
				result = reconcile
				return
			}
			result = nil
			s = o.slotLocked(key, true)
			if s == nil {
				return
			}
			s.local.Lock()
			defer s.local.Unlock()
			if s.source == nil {
				if enroll {
					s.observeLocked(owner, a, false)
				} else {
					s.source = a
				}
			}
			if s.detached || s.source != a {
				result = unverified
			}
		})
		return s, result
	})
}

// restoreCurrent attaches only the indexed row for an exact provider resident.
// Observations that accumulated while evicted are processed by the normal CAS loop.
func (o *nativeActionOwner) restoreCurrent(ctx context.Context, p EpisodeProjection, a *alert.Alert) (*episodeSlot, error) {
	if !o.live(ctx) || !sameResident(p, a) {
		return nil, unverified
	}
	s, err := o.sourceSlot(ctx, a, false)
	if err != nil {
		return nil, err
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	if s.latest() != a || !o.live(ctx) {
		return nil, unverified
	}
	if s.projection.ID != "" && s.projection.ID != p.ID {
		return nil, reconcile
	}
	if s.projection.ID == "" {
		if !sameResident(p, a) {
			return nil, reconcile
		}
		s.projection = p
		s.needsRestore = false
		o.mu.Lock()
		o.byID[p.EpisodeRef.EpisodeID] = s
		o.mu.Unlock()
	}
	return s, nil
}

func (o *nativeActionOwner) residentEpisode(ctx context.Context, ref EpisodeRef) (*episodeSlot, error) {
	s, err := o.episode(ref)
	if err == nil || o.readSource == nil || !validRef(ref) || ref.AuthorityID != o.authority {
		return s, err
	}
	var row *EpisodeProjection
	if err = o.read(ctx, "recover", map[string]any{"projection": "episode", "episode_id": ref.EpisodeID}, &row); err != nil {
		return nil, err
	}
	if row == nil || row.EpisodeRef.EpisodeID != ref.EpisodeID || row.EpisodeRef.Generation < ref.Generation || row.EpisodeRef.Generation == ref.Generation && row.EpisodeRef.VariantRevision < ref.VariantRevision || !managedUUID.MatchString(row.ID) {
		return nil, unverified
	}
	owner, err := o.projectionKey(*row)
	if err != nil {
		return nil, err
	}
	var a *alert.Alert
	o.readSource(owner, row.NativeVariant.Fingerprint, func(current *alert.Alert) { a = current })
	if !sameResident(*row, a) {
		return nil, unverified
	}
	epoch, _ := PublicationToken(ctx)
	p, err := o.ClassifyResident(ctx, epoch, a)
	if err != nil {
		return nil, err
	}
	if p == nil || p.ID != row.ID || p.EpisodeRef != row.EpisodeRef {
		return nil, reconcile
	}
	return o.restoreCurrent(ctx, *p, a)
}

type floorPlanRetryKey struct{}
type floorPlanRetry struct {
	source     *alert.Alert
	projection EpisodeProjection
}

// RetryFloorProjection identifies the issuing owner's exact prior projection
// during an authenticated retry of an ambiguous floor CAS. It is plan-only.
func RetryFloorProjection(ctx context.Context, s *alert.Alert) (EpisodeProjection, bool) {
	r, ok := ctx.Value(floorPlanRetryKey{}).(floorPlanRetry)
	return r.projection, ok && s == r.source
}
