// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"
)

func (o *nativeActionOwner) recoverWork(ctx context.Context, id string, seen map[string]bool) error {
	ctx = o.withEpoch(ctx)
	if seen[id] {
		return nil
	}
	if len(seen) >= 100 {
		return reconcile
	}
	seen[id] = true
	i, err := o.intent(ctx, id)
	if err != nil {
		return err
	}
	if i == nil {
		return reconcile
	}
	var successors []string
	if i.ReservationSuccessorID != nil {
		successors = append(successors, *i.ReservationSuccessorID)
	}
	for _, t := range i.Result.Targets {
		if t.SuccessorID != nil {
			successors = append(successors, *t.SuccessorID)
		}
	}
	for _, child := range successors {
		if !managedUUID.MatchString(child) {
			return reconcile
		}
		if err = o.recoverWork(ctx, child, seen); err != nil {
			return err
		}
	}
	r := i.Result
	var ordinary ordinaryRequest
	if err = json.Unmarshal(i.Request, &ordinary); err != nil {
		return reconcile
	}
	if ordinary.Terminal != nil {
		// Only a due ordinary group holding the provider pointer can drive this contact.
		// Close stale pending reservations without waking, renewing or replaying entered work.
		if slices.ContainsFunc(r.Targets, func(t TargetResult) bool { return t.State == "pending" }) {
			var out ActionResultV1
			return o.write(ctx, "reconcile-invalidated", map[string]any{"operation_id": id}, &out)
		}
		return nil
	}
	s, err := o.episode(r.EpisodeRef)
	if err != nil {
		o.mu.Lock()
		deferred := o.deferredRecovery
		o.mu.Unlock()
		if deferred {
			var p *EpisodeProjection
			if e := o.read(ctx, "recover", map[string]any{"projection": "episode", "episode_id": r.EpisodeRef.EpisodeID}, &p); e != nil {
				return e
			}
			if p == nil || p.EpisodeRef.EpisodeID != r.EpisodeRef.EpisodeID || p.EpisodeRef.AuthorityID != o.authority {
				return unverified
			}
			if p.State == "firing" && p.EpisodeRef.Generation == r.EpisodeRef.Generation {
				if e := o.restoreEpisode(*p); e != nil {
					return e
				}
				s, err = o.episode(r.EpisodeRef)
				if err != nil {
					return err
				}
			} else if p.State != "resolved" && p.EpisodeRef.Generation <= r.EpisodeRef.Generation {
				return unverified
			}
		}
	}
	if err != nil {
		// SQL independently proves invalidation. A missing live member gives no entry permission.
		var ignored ActionResultV1
		return o.write(ctx, "reconcile-invalidated", map[string]any{"operation_id": id}, &ignored)
	}
	var req ActionRequestV1
	explicit := ordinary.Kind != "ordinary"
	if explicit && (!decodeAction(i.Request, &req) || !validAction(req)) {
		return reconcile
	}
	s.turn.Lock()
	child, finished, err := o.reconcileLocked(ctx, s, i, req, explicit)
	s.turn.Unlock()
	if err != nil {
		return err
	}
	if child != "" {
		return o.recoverWork(ctx, child, seen)
	}
	if finished {
		return nil
	}
	if !explicit || i.Intent != nil && i.Intent.State == "accepted" {
		pending := slices.ContainsFunc(r.Targets, func(t TargetResult) bool { return t.State == "pending" && t.SuccessorID == nil })
		if !pending {
			return nil
		}
		if r.PermitExpiresAt == nil {
			return reconcile
		}
		if !time.Now().Before(o.localDeadline(*r.PermitExpiresAt)) {
			if req.PolicyBinding != nil {
				return nil
			}
			if !explicit {
				_, err = o.ReserveOrdinary(ctx, id, r.EpisodeRef, ordinary.Target, true)
			} else {
				_, err = o.Execute(ctx, req)
			}
			if err != nil {
				return err
			}
		}
		return o.dispatch.Wake(ctx, id)
	}
	// Fenced zero-target/local admissions are driven only by the authenticated caller.
	if dispatchKind(req.Kind) && r.State == "held" && i.ReservationSuccessorID == nil {
		_, err = o.Execute(ctx, req)
		return err
	}
	return nil
}

// reconcileLocked transfers only proven unstarted siblings. Each linked child independently
// revalidates its frozen request before a new permit or provider entry.
func (o *nativeActionOwner) reconcileLocked(ctx context.Context, s *episodeSlot, i *actionIntent, req ActionRequestV1, explicit bool) (string, bool, error) {
	r := i.Result
	closeObsolete := func() (string, bool, error) {
		var out ActionResultV1
		return "", true, o.write(ctx, "reconcile-invalidated", map[string]any{"operation_id": r.OperationID}, &out)
	}
	if err := o.flush(ctx, s); err != nil {
		if errors.Is(err, mismatch) || errors.Is(err, resolved) {
			return closeObsolete()
		}
		return "", true, err
	}
	p := s.projection
	source := s.latest()
	localErr := s.current(p, source, true)
	replaced := p.EpisodeRef.Generation == r.EpisodeRef.Generation && p.EpisodeRef.VariantRevision > r.EpisodeRef.VariantRevision
	if req.PolicyBinding != nil {
		if p.State == "resolved" || p.EpisodeRef.Generation != r.EpisodeRef.Generation || (p.EpisodeRef == r.EpisodeRef && p.SeverityRevision != r.SeverityRevision) {
			return closeObsolete()
		}
		// A live, already-accepted submission can finish. Only C3 can authorize a new attempt.
		if p.EpisodeRef != r.EpisodeRef || p.SeverityRevision != r.SeverityRevision || i.Intent == nil || i.Intent.State != "accepted" || r.PermitExpiresAt == nil || !o.localDeadline(*r.PermitExpiresAt).After(time.Now()) {
			return "", true, nil
		}
		return "", false, localErr
	}
	if explicit && localErr == nil && p.EpisodeRef.Generation == r.EpisodeRef.Generation {
		keys, routed := []string{}, []string{}
		empty := replaced && i.ReservationSuccessorID == nil && len(r.Targets) == 0 && i.Intent == nil && r.State == "held"
		for _, t := range r.Targets {
			if t.SuccessorID == nil && t.Evidence != nil && *t.Evidence != "DESTINATION_REMOVED" && (t.State == "no_effect" || replaced && t.State == "pending") {
				keys = append(keys, t.TargetKey)
			}
		}
		if empty || len(keys) > 0 {
			if err := o.verifySource(ctx, source, p.State); err != nil {
				return "", true, err
			}
			req.EpisodeRef = p.EpisodeRef
			routeView := p
			if req.TargetSeverity != nil && firingRanks[*req.TargetSeverity] > firingRanks[p.Floor] {
				routeView.Floor = *req.TargetSeverity
				routeView.SeverityRevision++
			}
			targets, reason, err := o.dispatch.Plan(ctx, source, routeView, req)
			if err != nil || reason != "" {
				return "", true, err
			}
			for _, t := range r.Targets {
				if slices.Contains(keys, t.TargetKey) && slices.ContainsFunc(targets, func(c DispatchTarget) bool { return reflect.DeepEqual(c, t.Target) }) {
					routed = append(routed, t.TargetKey)
				}
			}
			if err = s.current(p, source, true); err != nil {
				return "", true, err
			}
			var child ActionResultV1
			err = o.write(ctx, "supersede-not-started", map[string]any{"operation_id": r.OperationID, "current_ref": p.EpisodeRef, "expected_revision": p.SeverityRevision, "target_keys": keys, "routed_target_keys": routed}, &child)
			if err != nil {
				return "", true, err
			}
			if !managedUUID.MatchString(child.OperationID) {
				return "", true, reconcile
			}
			return child.OperationID, true, nil
		}
	}
	if p.State == "resolved" || p.EpisodeRef != r.EpisodeRef || p.SeverityRevision != r.SeverityRevision {
		return closeObsolete()
	}
	return "", false, localErr
}

func (l actionLease) currentEpoch(epoch uint64) bool {
	return epoch != 0 && l.Epoch == epoch && l.ExpiresAt.After(time.Now())
}

// recoverEpisodes advances a single recovery loop's frozen epoch. A failed page retains
// earlier progress only if the same lease still owns it.
func (o *nativeActionOwner) recoverEpisodes(ctx context.Context, epoch uint64) (err error) {
	o.mu.Lock()
	if !o.lease.currentEpoch(epoch) {
		o.mu.Unlock()
		return unavailable
	}
	c := o.bootCursor
	var invalidate []*episodeSlot
	if c.epoch != epoch {
		c.epoch, c.activeAfter, c.keyAfter, c.activeDone, c.keysDone = epoch, "", "", false, false
		for _, s := range o.byKey {
			invalidate = append(invalidate, s)
		}
	}
	o.mu.Unlock()
	// An intervening owner may have resolved a resident omitted from this epoch's firing scan.
	// Finish invalidation before publishing even the first cursor for this epoch.
	for _, s := range invalidate {
		s.turn.Lock()
		s.uncertain = s.uncertain || s.projection.LifecycleSeq > 0
		s.turn.Unlock()
	}
	defer func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		if !o.lease.currentEpoch(epoch) {
			err = unavailable
			return
		}
		o.bootCursor = c
	}()
	readPage := func(args map[string]any, out any) error {
		if err := o.read(ctx, "recover", args, out); err != nil {
			return err
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		if !o.lease.currentEpoch(epoch) {
			return unavailable
		}
		return nil
	}
	if !c.activeDone {
		const limit = 100
		args := map[string]any{"projection": "episodes", "limit": limit}
		if c.activeAfter != "" {
			args["after_id"] = c.activeAfter
		}
		var rows []EpisodeProjection
		if err := readPage(args, &rows); err != nil {
			return err
		}
		if rows == nil || len(rows) > limit {
			return unavailable
		}
		for _, p := range rows {
			if p.State != "firing" || !managedUUID.MatchString(p.ID) || p.ID <= c.activeAfter {
				return reconcile
			}
			if err := o.restoreEpisode(p); err != nil {
				return err
			}
			c.activeAfter = p.ID
		}
		c.activeDone = len(rows) < limit
	}
	if !c.keysDone {
		const limit = 64
		args := map[string]any{"projection": "membership", "limit": limit}
		if c.keyAfter != "" {
			args["after_key"] = c.keyAfter
		}
		var keys []string
		if err := readPage(args, &keys); err != nil {
			return err
		}
		if keys == nil || len(keys) > limit {
			return unavailable
		}
		for _, key := range keys {
			if key <= c.keyAfter {
				return reconcile
			}
			var binding string
			switch {
			case nativeFingerprint.MatchString(key):
				binding = sourceKey("", key)
			case managedHash.MatchString(key):
				binding = sourceKey(key, "")
			default:
				return reconcile
			}
			bucket, bit := membershipBit(binding)
			o.mu.Lock()
			if !o.lease.currentEpoch(epoch) {
				o.mu.Unlock()
				return unavailable
			}
			o.terminalMembership[bucket] |= bit
			o.mu.Unlock()
			c.keyAfter = key
		}
		c.keysDone = len(keys) < limit
	}
	if !c.activeDone || !c.keysDone {
		return unavailable
	}
	o.mu.Lock()
	var verify []*episodeSlot
	if o.deferredRecovery {
		for _, slot := range o.byKey {
			verify = append(verify, slot)
		}
	}
	o.mu.Unlock()
	for _, slot := range verify {
		slot.turn.Lock()
		slot.needsRestore = true
		slot.turn.Unlock()
	}
	return nil
}

func (o *nativeActionOwner) operationPage(ctx context.Context, after string) ([]ActionResultV1, error) {
	p := map[string]any{"projection": "operations", "limit": 32}
	if after != "" {
		p["after_id"] = after
	}
	var rows []ActionResultV1
	if err := o.read(ctx, "recover", p, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 32 {
		return nil, unavailable
	}
	for _, r := range rows {
		if !managedUUID.MatchString(r.OperationID) || r.OperationID <= after || !validRef(r.EpisodeRef) || r.EpisodeRef.AuthorityID != o.authority || r.Targets == nil {
			return nil, reconcile
		}
		after = r.OperationID
	}
	return rows, nil
}

func (o *nativeActionOwner) leaseTick(ctx context.Context) error {
	o.mu.Lock()
	old := o.lease
	o.mu.Unlock()
	if old.Epoch == 0 || !old.ExpiresAt.After(time.Now()) {
		var l actionLease
		if err := o.read(ctx, "acquire-authority", map[string]any{"owner_id": o.owner, "recipient_binding": 1}, &l); err != nil {
			return err
		}
		if !o.validLease(l) {
			return o.rejectLease()
		}
		old = l
	}
	start := time.Now()
	var l actionLease
	err := o.read(ctx, "renew-authority", map[string]any{"owner_id": o.owner, "epoch": old.Epoch, "recipient_binding": 1}, &l)
	if err != nil {
		return err
	}
	if !o.validLease(l) || l.Epoch != old.Epoch || l.RecipientKey != old.RecipientKey {
		return o.rejectLease()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	key, _ := hex.DecodeString(l.RecipientKey)
	if o.recipientKey != nil && !bytes.Equal(o.recipientKey, key) {
		o.lease.ExpiresAt = time.Time{}
		o.recovered = false
		return unavailable
	}
	o.recipientKey = key
	if o.lease.Epoch != l.Epoch {
		o.recovered = false
		clear(o.membership[:])
		clear(o.terminalMembership[:])
		for key := range o.byKey {
			bucket, bit := membershipBit(key)
			o.membership[bucket] |= bit
		}
	}
	// SQL sampled its clock after this request started. This deliberately shortens local validity by the round trip.
	o.dbAnchor = l.ExpiresAt.Add(-30 * time.Second)
	o.localAnchor = start
	l.ExpiresAt = start.Add(30 * time.Second)
	o.lease = l
	return nil
}

func (o *nativeActionOwner) rejectLease() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lease.ExpiresAt = time.Time{}
	o.recovered = false
	return unavailable
}

func (o *nativeActionOwner) validLease(l actionLease) bool {
	return l.RecipientBinding == 1 && managedHash.MatchString(l.RecipientKey) && l.Protocol == "native-action-store-v1" && l.RecoverySelectors == 1 && l.TerminalObservations == 2 && l.AuthorityID == o.authority && l.OwnerID == o.owner && l.Epoch > 0 && l.RenewSeconds == 10 && !l.ExpiresAt.IsZero()
}

// Drain observed changes even when an episode has no explicit operation or delivery pending.
func (o *nativeActionOwner) sweep(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var keys []string
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !o.ready() {
			continue
		}
		if len(keys) == 0 {
			o.mu.Lock()
			for k := range o.byKey {
				keys = append(keys, k)
			}
			o.mu.Unlock()
		}
		for n := 0; len(keys) > 0 && n < 100; n++ {
			key := keys[len(keys)-1]
			keys = keys[:len(keys)-1]
			s := o.slot(key, false)
			if s == nil || !s.turn.TryLock() {
				continue
			}
			o.sweepSlot(o.withEpoch(ctx), key, s)
			s.turn.Unlock()
		}
	}
}

// The caller owns turn. Provider GC can retire local quarantine without guessing a durable
// transition. Subsequent enrollment must read the durable source candidates before minting an ID.
func (o *nativeActionOwner) sweepSlot(ctx context.Context, key string, s *episodeSlot) {
	s.local.Lock()
	removed, observed := s.removed, s.observed
	changed := s.needsPublish || s.uncertain || s.overflow || s.ambiguous || len(s.pending) > 0 || s.source != nil && s.source.Resolved() && s.projection.State == "firing"
	// A full queue can lose intermediate identities. A terminal exact pair (including
	// the managed generation) still proves closure of its own durable variant.
	if s.overflow && removed && s.next == nil && !s.needsRestore && !s.ambiguous && s.projection.State == "firing" && s.source != nil && sameVariant(s.projection.NativeVariant, variantOf(s.source)) {
		m := s.projection.ManagedOwner
		if m == nil && !s.source.ManagedReceiver || m != nil && m.EpisodeKey == s.source.ManagedMember.Episode && m.Generation == s.source.ManagedMember.Generation {
			s.overflow = false
			s.pending = []actionEvent{{s.source, true}}
		}
	}
	abandoned := removed && s.next == nil && s.floorWrite == nil && (s.overflow || s.ambiguous)
	s.local.Unlock()
	if !changed {
		return
	}
	if !abandoned {
		err := o.flush(ctx, s)
		if err == nil {
			p := s.projection
			if p.State == "resolved" && removed {
				// A proven owner closure may retire a different unpromoted provider
				// member. Publish the committed tombstone without using it for delivery.
				if err = o.dispatch.Publish(ctx, p); err != nil {
					s.needsPublish = true
					return
				}
				s.needsPublish = false
			} else if s.latest() != nil && p.LifecycleSeq != 0 {
				_ = o.publish(ctx, s, p)
			}
			if p.State != "resolved" && !(removed && p.LifecycleSeq == 0) {
				return
			}
		} else if !removed || s.next != nil || !(errors.Is(err, unverified) || errors.Is(err, reconcile)) {
			return
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	s.local.Lock()
	defer s.local.Unlock()
	if !s.removed || s.floorWrite != nil || s.observed != observed || o.byKey[key] != s {
		return
	}
	s.detached = true
	delete(o.byKey, key)
	if id := s.projection.EpisodeRef.EpisodeID; o.byID[id] == s {
		delete(o.byID, id)
	}
	if s.projection.State != "resolved" || s.ambiguous || s.overflow {
		o.deferredRecovery = true
	}
}

func (o *nativeActionOwner) recoverAuthority(ctx context.Context, epoch uint64) error {
	if err := o.recoverEpisodes(ctx, epoch); err != nil {
		return err
	}
	if _, err := o.operationPage(ctx, ""); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.lease.currentEpoch(epoch) {
		return unavailable
	}
	o.recovered = true
	return nil
}

func (o *nativeActionOwner) maintain(ctx context.Context) {
	go o.sweep(ctx)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			_ = o.leaseTick(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	after := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		o.mu.Lock()
		lease := o.lease
		boot := !o.recovered
		o.mu.Unlock()
		if !lease.ExpiresAt.After(time.Now()) {
			continue
		}
		turn := context.WithValue(ctx, actionEpochKey{}, lease.Epoch)
		if boot {
			if err := o.recoverAuthority(turn, lease.Epoch); err != nil {
				continue
			}
			after = ""
		}
		if !o.live(turn) || !o.ready() {
			continue
		}
		rows, err := o.operationPage(turn, after)
		if err != nil {
			continue
		}
		if len(rows) == 0 {
			after = ""
			continue
		}
		for _, r := range rows {
			if ctx.Err() != nil {
				return
			}
			if !o.live(turn) {
				break
			}
			_ = o.recoverWork(turn, r.OperationID, map[string]bool{})
			after = r.OperationID
		}
	}
}

// linkedPolicyTransfer reads the exact already-transferred subset without granting new entry.
func (o *nativeActionOwner) linkedPolicyTransfer(ctx context.Context, i *actionIntent, q policyRecovery) (ActionResultV1, bool, error) {
	var result ActionResultV1
	id := ""
	if len(q.TargetKeys) == 0 {
		if i.ReservationSuccessorID == nil {
			return result, false, nil
		}
		id = *i.ReservationSuccessorID
	} else {
		for _, key := range q.TargetKeys {
			ix := slices.IndexFunc(i.Result.Targets, func(t TargetResult) bool { return t.TargetKey == key })
			if ix < 0 {
				return result, false, reconcile
			}
			if child := i.Result.Targets[ix].SuccessorID; child != nil {
				if id != "" && id != *child {
					return result, false, reconcile
				}
				id = *child
			}
		}
		if id == "" {
			return result, false, nil
		}
		for _, t := range i.Result.Targets {
			if slices.Contains(q.TargetKeys, t.TargetKey) && (t.SuccessorID == nil || *t.SuccessorID != id) {
				return result, false, reconcile
			}
		}
	}
	// The store verifies its original UUIDv5 including the transfer-time routed subset
	// and revision. The child's current result revision can change after commitment.
	err := o.read(ctx, "lookup", map[string]any{"projection": "transfer", "operation_id": i.Result.OperationID, "current_ref": q.CurrentRef, "expected_revision": q.SeverityRevision, "target_keys": q.TargetKeys}, &result)
	if err != nil {
		return ActionResultV1{}, false, err
	}
	if result.OperationID != id || result.EpisodeRef != q.CurrentRef {
		return ActionResultV1{}, false, reconcile
	}
	return result, true, nil
}

// transferPolicy transfers exactly one signed subset. It never commits or wakes its child.
func (o *nativeActionOwner) transferPolicy(ctx context.Context, s *episodeSlot, i *actionIntent, req ActionRequestV1, q policyRecovery, expires time.Time) (ActionResultV1, error) {
	var result ActionResultV1
	p := s.projection
	source := s.latest()
	if err := s.current(p, source, true); err != nil {
		return result, err
	}
	if err := o.verifySource(ctx, source, p.State); err != nil {
		return result, err
	}
	if q.CurrentRef.VariantRevision < req.EpisodeRef.VariantRevision {
		return result, mismatch
	}
	predecessor := i.Result
	routed := []string{}
	if len(q.TargetKeys) == 0 {
		if len(predecessor.Targets) != 0 || i.Intent != nil || p.EpisodeRef.VariantRevision <= req.EpisodeRef.VariantRevision {
			return result, reconcile
		}
	} else {
		for _, key := range q.TargetKeys {
			ix := slices.IndexFunc(predecessor.Targets, func(t TargetResult) bool { return t.TargetKey == key })
			if ix < 0 {
				return result, reconcile
			}
			t := predecessor.Targets[ix]
			if t.SuccessorID != nil || t.Evidence == nil || *t.Evidence == "DESTINATION_REMOVED" || t.State != "no_effect" && !(t.State == "pending" && p.EpisodeRef.VariantRevision > req.EpisodeRef.VariantRevision) {
				return result, reconcile
			}
		}
	}
	req.EpisodeRef = q.CurrentRef
	proposed := p
	if req.TargetSeverity != nil && firingRanks[*req.TargetSeverity] > firingRanks[p.Floor] {
		proposed.Floor = *req.TargetSeverity
		proposed.SeverityRevision++
	}
	candidates, reason, err := o.dispatch.Plan(ctx, source, proposed, req)
	if err != nil {
		return result, err
	}
	if reason != "" {
		return result, actionError{409, reason}
	}
	for _, t := range predecessor.Targets {
		if slices.Contains(q.TargetKeys, t.TargetKey) && slices.ContainsFunc(candidates, func(c DispatchTarget) bool { return reflect.DeepEqual(c, t.Target) }) {
			routed = append(routed, t.TargetKey)
		}
	}
	if err = s.current(p, source, true); err != nil {
		return result, err
	}
	if !time.Now().Before(expires) {
		return result, actionError{403, "POLICY_ASSERTION_EXPIRED"}
	}
	err = o.write(ctx, "supersede-not-started", map[string]any{"operation_id": predecessor.OperationID, "current_ref": q.CurrentRef, "expected_revision": q.SeverityRevision, "target_keys": q.TargetKeys, "routed_target_keys": routed}, &result)
	if err != nil {
		lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		saved, e := o.intent(lookup, predecessor.OperationID)
		if e == nil && saved != nil && saved.Digest == i.Digest {
			child, found, e := o.linkedPolicyTransfer(lookup, saved, q)
			if found && e == nil {
				return child, nil
			}
		}
	}
	return result, err
}
