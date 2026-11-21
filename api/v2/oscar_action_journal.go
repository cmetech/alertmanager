// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"time"

	"github.com/prometheus/alertmanager/alert"
)

// Entry contains the private original-attempt token. Only this entry may settle
// its late receipt. Call Valid again immediately before native provider entry.
type Entry struct {
	OperationID, TargetKey, token string
	ref                           EpisodeRef
	revision                      uint64
	logicalID                     *string
	target                        DispatchTarget
	expires                       time.Time
	valid                         func() bool
	ready                         func() bool
}

func (e Entry) Valid() bool { return (e.ready == nil || e.ready()) && e.LocalValid() }

// LocalValid checks the lease, publication and source after all blocking preparation is complete.
func (e Entry) LocalValid() bool { return e.valid != nil && e.valid() && time.Now().Before(e.expires) }

// ActionJournal is the pipeline's A3 handoff. Until Bind returns and Version
// reports 1 the A4 reader must fence tracked ordinary delivery and callback signing.
type ActionJournal interface {
	ObservationValid(*alert.Alert, EpisodeProjection) bool
	InspectOrdinary(context.Context, *alert.Alert) (*EpisodeProjection, *OrdinaryPass, error)
	Lookup(context.Context, string) (ActionResultV1, error)
	Delivery(context.Context, *alert.Alert, string, string, *Entry) (alert.NativeDeliveryV1, error)
	Project(context.Context, *alert.Alert) (EpisodeProjection, error)
	ReserveOrdinary(context.Context, string, EpisodeRef, DispatchTarget, bool) (ActionResultV1, error)
	Claim(context.Context, string, string) (Entry, error)
	Settle(context.Context, Entry, string, string) (ActionResultV1, error)
}

func (o *nativeActionOwner) localDeadline(db time.Time) time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.dbAnchor.IsZero() {
		return db
	}
	return o.localAnchor.Add(db.Sub(o.dbAnchor))
}

// Delivery stamps a current, durably projected provider member for A1's exact-body builder.
// A4 supplies a stable delivery UUID and the original claimed entry for a tracked contact.
func (o *nativeActionOwner) Delivery(ctx context.Context, source *alert.Alert, receiver, id string, entry *Entry) (alert.NativeDeliveryV1, error) {
	p, err := o.Project(ctx, source)
	if err != nil {
		return alert.NativeDeliveryV1{}, err
	}
	d := alert.NativeDeliveryV1{Version: 1, EpisodeRef: p.EpisodeRef, NativeVariant: p.NativeVariant, LifecycleSeq: p.LifecycleSeq, State: p.State, ActiveSince: p.ActiveSince, SourceSeverity: p.SourceSeverity, EffectiveSeverity: p.EffectiveSeverity(), DeliveryID: id, TargetScope: []ScopeEntry{}}
	if entry != nil {
		if !entry.Valid() || entry.ref != p.EpisodeRef || entry.revision != p.SeverityRevision || entry.target.ReceiverID != receiver {
			return d, reconcile
		}
		d.OperationID = entry.logicalID
		d.TargetScope = entry.target.Scope
	} else if p.Floor != "" && p.State == "firing" {
		return d, reconcile
	}
	return d, d.Validate(receiver)
}

func (o *nativeActionOwner) ReserveOrdinary(ctx context.Context, id string, ref EpisodeRef, target DispatchTarget, renew bool) (ActionResultV1, error) {
	ctx = o.withEpoch(ctx)
	var r ActionResultV1
	if !o.ready() || !managedUUID.MatchString(id) {
		return r, unavailable
	}
	s, err := o.episode(ref)
	if err != nil {
		return r, err
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	if err = o.flush(ctx, s); err != nil {
		return r, err
	}
	p := s.projection
	source := s.latest()
	if ref != p.EpisodeRef {
		return r, mismatch
	}
	if err = s.current(p, source, true); err != nil {
		return r, err
	}
	if err = o.verifySource(ctx, source, p.State); err != nil {
		return r, err
	}
	req := ActionRequestV1{EpisodeRef: ref, Kind: "ordinary", TargetScope: target.Scope}
	targets, reason, err := o.dispatch.Plan(ctx, source, p, req)
	if err != nil {
		return r, err
	}
	if reason != "" || !slices.ContainsFunc(targets, func(t DispatchTarget) bool { return reflect.DeepEqual(target, t) }) {
		return r, reconcile
	}
	if err = s.current(p, source, true); err != nil {
		return r, err
	}
	err = o.write(ctx, "reserve-coverage", map[string]any{"operation_id": id, "ref": ref, "target": target, "expected_revision": p.SeverityRevision, "renew_permit": renew}, &r)
	if err != nil {
		record, e := o.resolveIntent(ctx, id)
		if e != nil || record == nil {
			return r, err
		}
		var old ordinaryRequest
		if json.Unmarshal(record.Request, &old) != nil || old.Kind != "ordinary" || old.EpisodeRef != ref || old.OperationID != id || old.SeverityRevision != p.SeverityRevision || !reflect.DeepEqual(old.Target, target) {
			return r, conflict
		}
		r = record.Result
		if renew && (r.PermitExpiresAt == nil || !o.localDeadline(*r.PermitExpiresAt).After(time.Now())) {
			return r, err
		}
	}
	if !o.live(ctx) {
		return ActionResultV1{}, unavailable
	}
	return r, s.current(p, source, true)
}

type ordinaryRequest struct {
	Kind             string         `json:"kind"`
	OperationID      string         `json:"operation_id"`
	EpisodeRef       EpisodeRef     `json:"episode_ref"`
	Target           DispatchTarget `json:"target"`
	SeverityRevision uint64         `json:"severity_revision"`
}

func (o *nativeActionOwner) Claim(ctx context.Context, id, key string) (Entry, error) {
	ctx = o.withEpoch(ctx)
	if !o.ready() {
		return Entry{}, unavailable
	}
	i, err := o.intent(ctx, id)
	if err != nil {
		return Entry{}, err
	}
	if i == nil {
		return Entry{}, unverified
	}
	r := i.Result
	idx := slices.IndexFunc(r.Targets, func(t TargetResult) bool { return t.TargetKey == key && t.State == "pending" && t.SuccessorID == nil })
	if idx < 0 {
		return Entry{}, reconcile
	}
	var req ActionRequestV1
	var ordinary ordinaryRequest
	if err = json.Unmarshal(i.Request, &ordinary); err != nil {
		return Entry{}, reconcile
	}
	if ordinary.Kind == "ordinary" {
		req = ActionRequestV1{Kind: "ordinary", EpisodeRef: r.EpisodeRef, TargetScope: ordinary.Target.Scope}
	} else if !decodeAction(i.Request, &req) || !validAction(req) {
		return Entry{}, reconcile
	}
	s, err := o.episode(r.EpisodeRef)
	if err != nil {
		return Entry{}, err
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	if err = o.flush(ctx, s); err != nil {
		return Entry{}, err
	}
	p := s.projection
	source := s.latest()
	if p.EpisodeRef != r.EpisodeRef || p.SeverityRevision != r.SeverityRevision {
		return Entry{}, mismatch
	}
	if err = s.current(p, source, true); err != nil {
		return Entry{}, err
	}
	if err = o.verifySource(ctx, source, p.State); err != nil {
		return Entry{}, err
	}
	candidates, reason, err := o.dispatch.Plan(ctx, source, p, req)
	if err != nil {
		return Entry{}, err
	}
	if reason != "" || !slices.ContainsFunc(candidates, func(t DispatchTarget) bool { return reflect.DeepEqual(t, r.Targets[idx].Target) }) {
		return Entry{}, reconcile
	}
	if r.PermitExpiresAt == nil || !time.Now().Before(o.localDeadline(*r.PermitExpiresAt)) {
		return Entry{}, actionError{409, "NATIVE_PERMIT_EXPIRED"}
	}
	if err = s.current(p, source, true); err != nil {
		return Entry{}, err
	}
	var entry struct {
		Token  string    `json:"entry_token"`
		Lease  time.Time `json:"lease_expires_at"`
		Permit time.Time `json:"permit_expires_at"`
	}
	o.mu.Lock()
	epoch := o.lease.Epoch
	o.mu.Unlock()
	if err = o.write(ctx, "claim-target", map[string]any{"operation_id": id, "target_key": key}, &entry); err != nil {
		// A response arriving after the local cutoff may still contain our original token.
		if managedHash.MatchString(entry.Token) {
			_, _ = o.Settle(ctx, Entry{OperationID: id, TargetKey: key, token: entry.Token}, "no_effect", "LEASE_EXPIRED_BEFORE_PROVIDER_ENTRY")
		} else {
			_, _ = o.resolveIntent(ctx, id)
		}
		return Entry{}, reconcile
	}
	until := o.localDeadline(entry.Lease)
	if d := o.localDeadline(entry.Permit); d.Before(until) {
		until = d
	}
	if !managedHash.MatchString(entry.Token) {
		return Entry{}, reconcile
	}
	s.local.Lock()
	generation := s.publication
	s.local.Unlock()
	var logical *string
	if ordinary.Kind != "ordinary" {
		if !managedUUID.MatchString(i.LogicalActionID) {
			return Entry{}, reconcile
		}
		logical = &i.LogicalActionID
	}
	e := Entry{OperationID: id, TargetKey: key, token: entry.Token, ref: r.EpisodeRef, revision: r.SeverityRevision, logicalID: logical, target: r.Targets[idx].Target, expires: until, ready: o.ready, valid: func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		s.local.Lock()
		defer s.local.Unlock()
		return o.recovered && o.lease.Epoch == epoch && o.lease.ExpiresAt.After(time.Now()) && s.publication == generation && s.currentLocked(p, source, true) == nil
	}}
	if !e.Valid() {
		_, err = o.Settle(ctx, e, "no_effect", "INVALIDATED_BEFORE_PROVIDER_ENTRY")
		if err != nil {
			return Entry{}, err
		}
		return Entry{}, reconcile
	}
	return e, nil
}
func (o *nativeActionOwner) Settle(ctx context.Context, e Entry, outcome, evidence string) (ActionResultV1, error) {
	var r ActionResultV1
	if !managedUUID.MatchString(e.OperationID) || !managedHash.MatchString(e.TargetKey) || !managedHash.MatchString(e.token) || outcome != "confirmed" && outcome != "unknown" && outcome != "no_effect" || evidence == "" || len(evidence) > 255 {
		return r, conflict
	}
	err := o.read(ctx, "settle-target", map[string]any{"operation_id": e.OperationID, "target_key": e.TargetKey, "entry_token": e.token, "receipt": map[string]string{"outcome": outcome, "evidence": evidence}}, &r)
	return r, err
}

// OrdinaryPass is a local entry fence for a verified untracked provider member.
type OrdinaryPass struct {
	Enter func() bool
	// Finish releases conclusive entries. Unknown acceptance keeps the source fenced.
	Finish func(conclusive bool)
}

// InspectOrdinary checks membership without enrolling an unknown source.
func (o *nativeActionOwner) InspectOrdinary(ctx context.Context, source *alert.Alert) (*EpisodeProjection, *OrdinaryPass, error) {
	if source == nil || o.readSource == nil {
		return nil, nil, unverified
	}
	fp, owner := source.Fingerprint().String(), source.ManagedMember.Episode
	key := sourceKey(owner, fp)
	bucket, bit := membershipBit(key)
	o.mu.Lock()
	epoch := o.lease.Epoch
	enrollments := o.enrollments
	live := o.recovered && o.lease.ExpiresAt.After(time.Now())
	tracked := o.byKey[key] != nil
	candidate := o.membership[bucket]&bit != 0
	held := o.untracked[key] != 0
	o.mu.Unlock()
	if !live || held {
		return nil, nil, reconcile
	}
	if !tracked && candidate {
		var rows []EpisodeProjection
		var managed any
		if owner != "" {
			managed = owner
		}
		if err := o.read(ctx, "recover", map[string]any{"projection": "source", "fingerprint": fp, "managed_key": managed}, &rows); err != nil {
			return nil, nil, err
		}
		if rows == nil || len(rows) > 1 {
			return nil, nil, reconcile
		}
		if len(rows) == 1 {
			row := rows[0]
			currentOwner, err := o.projectionKey(row)
			if err != nil || row.State != "firing" || !managedUUID.MatchString(row.ID) || currentOwner != owner || owner == "" && row.NativeVariant.Fingerprint != fp {
				return nil, nil, reconcile
			}
			if err := o.restoreEpisode(row); err != nil {
				return nil, nil, err
			}
			tracked = true
		}
	}
	if tracked {
		p, err := o.projectSource(ctx, source, false)
		return &p, nil, err
	}
	entered := false
	pass := &OrdinaryPass{}
	pass.Enter = func() bool {
		ok := false
		o.readSource(owner, fp, func(current *alert.Alert) {
			o.mu.Lock()
			defer o.mu.Unlock()
			if current == source && !entered && o.recovered && o.lease.Epoch == epoch && o.lease.ExpiresAt.After(time.Now()) && o.byKey[key] == nil && o.untracked[key] == 0 && len(o.untracked) < maxActionEpisodes &&
				(candidate && o.enrollments == enrollments || !candidate && o.membership[bucket]&bit == 0) {
				o.untracked[key] = 1
				entered, ok = true, true
			}
		})
		return ok
	}
	pass.Finish = func(conclusive bool) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if entered && conclusive {
			delete(o.untracked, key)
		}
		entered = false
	}
	return nil, pass, nil
}

// membershipBit only selects candidates for the indexed source lookup.
func membershipBit(key string) (uint16, uint64) {
	sum := sha256.Sum256([]byte(key))
	return binary.BigEndian.Uint16(sum[:2]), uint64(1) << (sum[2] & 63)
}

// ObservationValid checks local lifecycle and lease state for a signed terminal observation.
func (o *nativeActionOwner) ObservationValid(source *alert.Alert, p EpisodeProjection) bool {
	s, err := o.episode(p.EpisodeRef)
	if err != nil || !o.ready() {
		return false
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	return !s.uncertain && s.projection.EpisodeRef == p.EpisodeRef && s.projection.LifecycleSeq == p.LifecycleSeq && s.projection.SeverityRevision == p.SeverityRevision && s.current(s.projection, source, false) == nil
}
