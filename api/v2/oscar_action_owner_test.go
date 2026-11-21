// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

type actionRPCFunc func(context.Context, string, map[string]any, any) error

func (f actionRPCFunc) call(c context.Context, k string, p map[string]any, v any) error {
	return f(c, k, p, v)
}

type testActionDispatch struct{ ActionDispatch }

func (testActionDispatch) Version() int { return 1 }
func (testActionDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return []DispatchTarget{}, "", nil
}
func (testActionDispatch) Publish(context.Context, EpisodeProjection) error { return nil }
func (testActionDispatch) Wake(context.Context, string) error               { return nil }

func TestOscarActionPersistenceLossAndInvalidation(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"reserve", "commit", "resolve-during-commit", "expired-permit", "operation-conflict"} {
		t.Run(failure, func(t *testing.T) {
			var req ActionRequestV1
			require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
			source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Minute), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
			var o *nativeActionOwner
			var record *actionIntent
			var renewed bool
			var writes int
			rpc := actionRPCFunc(func(ctx context.Context, cmd string, p map[string]any, out any) error {
				var value any
				switch cmd {
				case "lookup":
					value = record
				case "reserve":
					writes++
					record = &actionIntent{Digest: p["digest"].(string), Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held"}, Request: mustRaw(t, req)}
					if failure == "operation-conflict" {
						record.Digest = strings.Repeat("0", 64)
					}
					if failure == "reserve" || failure == "operation-conflict" {
						return errors.New("lost reserve reply")
					}
					value = record.Result
				case "commit":
					writes++
					update := p["update"].(actionCommit)
					record.Intent = &update
					record.Result.State = "accepted"
					expiry := time.Now().Add(30 * time.Second)
					if p["renew_permit"] == true {
						renewed = true
					}
					record.Result.PermitExpiresAt = &expiry
					if failure == "resolve-during-commit" {
						other := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "other"}, StartsAt: source.StartsAt, EndsAt: source.EndsAt}, source.UpdatedAt, false)
						o.observe("", other, false)
						_, err := o.Project(ctx, other)
						require.NoError(t, err)
						closed := *source
						closed.EndsAt = time.Now()
						o.observe("", &closed, false)
					}
					if failure == "commit" {
						return errors.New("lost commit reply")
					}
					value = record.Result
				case "project-episode":
					u := p["update"].(episodeUpdate)
					value = EpisodeProjection{episodeUpdate: u}
				case "reconcile-invalidated":
					value = record.Result
				default:
					t.Fatalf("unexpected %s", cmd)
				}
				b, err := json.Marshal(value)
				require.NoError(t, err)
				return json.Unmarshal(b, out)
			})
			o = newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, testActionDispatch{})
			o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
			o.recovered = true
			o.observe("", source, false)
			proj, err := o.Project(t.Context(), source)
			require.NoError(t, err)
			req.EpisodeRef = proj.EpisodeRef
			_, err = o.Execute(t.Context(), req)
			if failure == "operation-conflict" {
				require.ErrorIs(t, err, conflict)
				return
			}
			if failure == "resolve-during-commit" {
				require.ErrorIs(t, err, mismatch)
				return
			}
			require.NoError(t, err)
			if failure == "expired-permit" {
				expired := time.Now().Add(-time.Second)
				record.Result.PermitExpiresAt = &expired
				_, err = o.Execute(t.Context(), req)
				require.NoError(t, err)
				require.True(t, renewed)
			}
			if failure == "reserve" || failure == "commit" {
				require.Equal(t, 2, writes)
			}
		})
	}
}
func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestOscarActionRecoveryRequiresExactSource(t *testing.T) {
	t.Parallel()
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	owner := newNativeActionOwner(defaultActionAuthority, nil, testActionDispatch{})
	proj := EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "11111111-1111-4111-8111-111111111113", Generation: 1, VariantRevision: 1}, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", ActiveSince: source.StartsAt.UTC().Format(time.RFC3339Nano), LifecycleSeq: 1}, Floor: "critical", SeverityRevision: 1}
	owner.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
	owner.recovered = true
	require.NoError(t, owner.restoreEpisode(proj))
	other := *source
	other.StartsAt = source.StartsAt.Add(time.Nanosecond)
	owner.observe("", &other, false)
	_, err := owner.Project(t.Context(), &other)
	require.ErrorIs(t, err, unverified)
}

func TestOscarActionRecoveryFollowsReservationAndTargetSuccessors(t *testing.T) {
	t.Parallel()
	ids := []string{"11111111-1111-4111-8111-111111111111", "11111111-1111-4111-8111-111111111112", "11111111-1111-4111-8111-111111111113"}
	ref := EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "11111111-1111-4111-8111-111111111114", Generation: 1, VariantRevision: 1}
	for _, zero := range []bool{true, false} {
		looked := map[string]int{}
		rpc := actionRPCFunc(func(ctx context.Context, cmd string, p map[string]any, out any) error {
			id := p["operation_id"].(string)
			if cmd == "reconcile-invalidated" {
				require.Equal(t, uint64(2), p["epoch"])
				return nil
			}
			require.Equal(t, "lookup", cmd)
			require.Equal(t, "intent", p["projection"])
			looked[id]++
			i := actionIntent{Digest: strings.Repeat("b", 64), Result: ActionResultV1{OperationID: id, EpisodeRef: ref}}
			if id == ids[0] {
				if zero {
					i.ReservationSuccessorID = &ids[1]
				} else {
					i.Result.Targets = []TargetResult{{SuccessorID: &ids[1]}, {SuccessorID: &ids[2]}}
				}
			}
			return json.Unmarshal(mustRaw(t, i), out)
		})
		o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
		o.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
		o.recovered = true
		require.NoError(t, o.recoverWork(t.Context(), ids[0], map[string]bool{}))
		require.Equal(t, 1, looked[ids[0]])
		require.Equal(t, 1, looked[ids[1]])
		if !zero {
			require.Equal(t, 1, looked[ids[2]])
		}
	}
}

func TestOscarActionExpiredWriterMayOnlySettleOriginalEntry(t *testing.T) {
	t.Parallel()
	id := "11111111-1111-4111-8111-111111111111"
	token := strings.Repeat("d", 64)
	key := strings.Repeat("f", 64)
	settled := false
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, _ any) error {
		require.Equal(t, "settle-target", cmd)
		require.Equal(t, token, p["entry_token"])
		require.NotContains(t, p, "owner_id")
		require.NotContains(t, p, "epoch")
		settled = true
		return nil
	})
	o := newNativeActionOwner(defaultActionAuthority, rpc, testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	stale := o.withEpoch(t.Context())
	o.lease.Epoch = 2
	require.ErrorIs(t, o.write(stale, "commit", map[string]any{}, nil), unavailable)
	o.lease.ExpiresAt = time.Now().Add(-time.Second)
	require.ErrorIs(t, o.write(o.withEpoch(t.Context()), "claim-target", map[string]any{}, nil), unavailable)
	_, err := o.Settle(t.Context(), Entry{OperationID: id, TargetKey: key, token: token}, "confirmed", "original attempt receipt")
	require.NoError(t, err)
	require.True(t, settled)
}

func TestOscarActionReadinessNeedsVersionAndRejectsConflictingLease(t *testing.T) {
	t.Parallel()
	var o *nativeActionOwner
	protocol := "old-store"
	selectors := 0
	foreign := false
	rpc := actionRPCFunc(func(_ context.Context, cmd string, _ map[string]any, out any) error {
		if foreign {
			return unavailable
		}
		return json.Unmarshal(mustRaw(t, actionLease{Protocol: protocol, RecoverySelectors: selectors, OwnerID: o.owner, AuthorityID: o.authority, Epoch: 1, ExpiresAt: time.Now().Add(30 * time.Second), RenewSeconds: 10}), out)
	})
	o = newNativeActionOwner(defaultActionAuthority, rpc, nil)
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	require.False(t, o.ready())
	foreign = true
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	foreign = false
	protocol = "native-action-store-v1"
	require.ErrorIs(t, o.leaseTick(t.Context()), unavailable)
	selectors = 1
	require.NoError(t, o.leaseTick(t.Context()))
	o.recovered = true
	require.False(t, o.ready())
	o.dispatch = testActionDispatch{}
	require.True(t, o.ready())
}

func TestOscarActionEligibilityResolvedAndReplacedIsReadOnly(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(context.Context, string, map[string]any, any) error {
		t.Fatal("eligibility wrote or read the durable action journal")
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	end := time.Now().Add(-time.Second)
	a := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: end.Add(-time.Minute), EndsAt: end}, end, false)
	current := req.EpisodeRef
	current.VariantRevision++
	o.byID[current.EpisodeID] = &episodeSlot{source: a, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: current, State: "resolved", NativeVariant: variantOf(a)}}}
	items, err := o.Eligibility(t.Context(), []EpisodeRef{req.EpisodeRef, current})
	require.NoError(t, err)
	require.Len(t, items, 2)
	for n, reason := range []string{mismatch.reason, resolved.reason} {
		for kind := range actionGrants {
			decision := items[n].Actions[kind]
			require.False(t, decision.Allowed)
			require.Equal(t, reason, *decision.Reason)
		}
	}
}

func TestOscarActionPolicyRecoveryRequiresFreshFencedSubmission(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	next := req.EpisodeRef
	next.VariantRevision++
	digest, err := actionDigest(req)
	require.NoError(t, err)
	record := actionIntent{Digest: digest, Request: mustRaw(t, req), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held", Targets: []TargetResult{}}}
	transfers := 0
	childID := "77777777-1111-4111-8111-111111111111"
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			if p["projection"] == "transfer" {
				if p["expected_revision"] != uint64(0) {
					return reconcile
				}
				return json.Unmarshal(mustRaw(t, ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}), out)
			}
			if p["operation_id"] == childID {
				child := actionIntent{SupersedesOperationID: &req.OperationID, Digest: strings.Repeat("a", 64), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}}
				return json.Unmarshal(mustRaw(t, child), out)
			}
			return json.Unmarshal(mustRaw(t, record), out)
		case "supersede-not-started":
			transfers++
			record.ReservationSuccessorID = &childID
			require.Equal(t, next, p["current_ref"])
			return json.Unmarshal(mustRaw(t, ActionResultV1{OperationID: childID, EpisodeRef: next, State: "held"}), out)
		default:
			t.Fatalf("unexpected policy mutation %s", cmd)
			return nil
		}
	})
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, testActionDispatch{})
	o.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.byID[next.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: next, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", LifecycleSeq: 2}}}
	require.NoError(t, o.recoverWork(t.Context(), req.OperationID, map[string]bool{}))
	require.Zero(t, transfers)
	_, err = o.Execute(t.Context(), req)
	require.Error(t, err)
	original := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{})
	got, err := o.Execute(original, req)
	require.NoError(t, err)
	require.Equal(t, "held", got.State)
	require.Zero(t, transfers)
	directive := policyRecovery{Mode: "transfer", CurrentRef: next, TargetKeys: []string{}}
	fresh := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{Recovery: &directive, ExpiresAt: time.Now().Add(10 * time.Second)})
	got, err = o.Execute(fresh, req)
	require.NoError(t, err)
	require.Equal(t, childID, got.OperationID)
	require.Equal(t, 1, transfers)
	replay, err := o.Execute(fresh, req)
	require.NoError(t, err)
	require.Equal(t, childID, replay.OperationID)
	require.Equal(t, 1, transfers)
}

type heldPolicyDispatch struct{ testActionDispatch }

func (heldPolicyDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return nil, "NATIVE_SUPPRESSED", nil
}

func TestOscarActionSuppressedPolicyReservationRemainsTransferable(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.NoError(t, json.Unmarshal([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	var record *actionIntent
	rpc := actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			return json.Unmarshal(mustRaw(t, record), out)
		case "reserve":
			reason := "AWAITING_NATIVE_COMMIT"
			record = &actionIntent{Digest: p["digest"].(string), Request: mustRaw(t, req), LogicalActionID: req.OperationID, Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, State: "held", Reason: &reason}}
			return json.Unmarshal(mustRaw(t, record.Result), out)
		default:
			t.Fatalf("suppressed policy produced %s", cmd)
			return nil
		}
	})
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, rpc, heldPolicyDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", LifecycleSeq: 1}}}
	ctx := context.WithValue(t.Context(), policyAssertionKey{}, policyAssertion{})
	got, err := o.Execute(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "NATIVE_SUPPRESSED", *got.Reason)
	require.Nil(t, record.Intent)
	replay, err := o.Execute(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "AWAITING_NATIVE_COMMIT", *replay.Reason)
}

func TestActionManagedTransitionsRequireDurableOwnerEvidence(t *testing.T) {
	for _, kind := range []string{"update", "clear"} {
		t.Run(kind, func(t *testing.T) {
			key := strings.Repeat("b", 64)
			old := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
			old.ManagedReceiver, old.ManagedOperationKind = true, "raise"
			old.ManagedMember = alert.ManagedMembership{Episode: key, Generation: 1, Event: "11111111-1111-4111-8111-111111111111", Digest: strings.Repeat("d", 64)}
			candidate := *old
			candidate.ManagedOperationKind = kind
			candidate.ManagedMember.Generation = 2
			candidate.ManagedMember.Event = "22222222-1111-4111-8111-111111111111"
			mkSlot := func(a *alert.Alert) *ownerSlot {
				return &ownerSlot{Generation: a.ManagedMember.Generation, Projection: snapshot(a), Operation: mustRaw(t, map[string]string{"kind": a.ManagedOperationKind, "event_id": a.ManagedMember.Event, "source_digest": a.ManagedMember.Digest})}
			}
			row := ownerState{Key: key, State: "open", Phase: "settled", Current: mkSlot(old), Generation: 1}
			var writes []episodeUpdate
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
				require.Equal(t, "project-episode", cmd)
				u := p["update"].(episodeUpdate)
				writes = append(writes, u)
				*out.(*EpisodeProjection) = EpisodeProjection{ID: "33333333-1111-4111-8111-111111111111", episodeUpdate: u, Floor: "critical", SeverityRevision: 1}
				return nil
			}), testActionDispatch{})
			o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
			o.recovered = true
			o.verifyManaged = func(_ context.Context, a *alert.Alert, state string) error { return actionMemberProof(row, a, state) }
			o.observe(key, old, false)
			first, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			row.Phase, row.Generation, row.Pending = "reserved", 2, mkSlot(&candidate)
			o.observe(key, &candidate, false)
			s := o.slot(sourceKey(key, ""), false)
			require.Error(t, o.flush(o.withEpoch(t.Context()), s))
			require.Len(t, writes, 1)
			// Restart can restore the predecessor and cancel a prior epoch's pending stamp.
			row.Phase, row.Generation, row.Pending = "cancelled", 3, nil
			o.observe(key, old, false)
			p, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			require.Equal(t, first.EpisodeRef, p.EpisodeRef)
			require.Equal(t, "critical", p.Floor)
			// A fresh native coordinator reattaches only the previously journaled predecessor.
			restarted := newNativeActionOwner(o.authority, o.rpc, o.dispatch)
			restarted.lease = actionLease{Epoch: 2, ExpiresAt: time.Now().Add(time.Minute)}
			restarted.recovered = true
			restarted.verifyManaged = o.verifyManaged
			require.NoError(t, restarted.restoreEpisode(p))
			restarted.observe(key, old, false)
			recovered, err := restarted.Project(t.Context(), old)
			require.NoError(t, err)
			require.Equal(t, first.EpisodeRef, recovered.EpisodeRef)
			require.Equal(t, "critical", recovered.Floor)
			o = restarted
			s = o.slot(sourceKey(key, ""), false)
			candidate.ManagedMember.Generation = 4
			row.Current, row.Phase, row.Generation = mkSlot(&candidate), "applied", 4
			if kind == "clear" {
				closed := time.Now().UnixMilli()
				row.Closed = &closed
				row.State = "exact_closed"
			}
			o.observe(key, &candidate, false)
			p, err = o.Project(t.Context(), &candidate)
			require.NoError(t, err)
			require.Equal(t, uint64(2), p.EpisodeRef.VariantRevision)
			if kind == "clear" {
				require.Equal(t, "resolved", p.State)
			} else {
				require.Equal(t, "firing", p.State)
				// Administrative closure retires the proven projection, even with a different unpromoted pending stamp.
				other := candidate
				other.ManagedMember.Generation = 5
				row.Pending, row.Generation, row.Phase = mkSlot(&other), 5, "reserved"
				o.observe(key, &other, false)
				closed := time.Now().UnixMilli()
				row.Closed = &closed
				row.State, row.Phase, row.Generation = "exact_closed", "closing", 6
				o.observe(key, nil, true)
				require.NoError(t, o.flush(o.withEpoch(t.Context()), s))
				require.Equal(t, p.EpisodeRef, s.projection.EpisodeRef)
				require.Equal(t, "resolved", s.projection.State)
			}
		})
	}
}

func TestPolicyInvalidationReleasesOnlyOriginalSameVariantOperation(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Actor = ActionActor{Kind: "policy", ID: "policy"}
	req.Kind = "resend"
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	escalationID := "22222222-1111-4111-8111-111111111111"
	ops := map[string]*actionIntent{req.OperationID: {Request: mustRaw(t, req), Digest: strings.Repeat("a", 64), Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef, SeverityRevision: 0, Targets: []TargetResult{{State: "pending"}, {State: "unknown"}, {State: "confirmed"}}}}, escalationID: {Result: ActionResultV1{OperationID: escalationID, EpisodeRef: req.EpisodeRef, SeverityRevision: 1}}}
	var reconciled []string
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		id := p["operation_id"].(string)
		switch cmd {
		case "lookup":
			return json.Unmarshal(mustRaw(t, ops[id]), out)
		case "reconcile-invalidated":
			reconciled = append(reconciled, id)
			return nil
		default:
			t.Fatalf("unauthorized %s", cmd)
			return nil
		}
	}), testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", NativeVariant: variantOf(source)}, SeverityRevision: ops[escalationID].Result.SeverityRevision}}
	require.NoError(t, o.recoverWork(t.Context(), req.OperationID, map[string]bool{}))
	require.Equal(t, []string{req.OperationID}, reconciled)
}

type singleActionDispatch struct {
	testActionDispatch
	target DispatchTarget
}

func (d singleActionDispatch) Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error) {
	return []DispatchTarget{d.target}, "", nil
}

func TestFloorCommitFencesOutstandingEntryBeforeLostReply(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	sev := "critical"
	req.Kind, req.TargetSeverity = "escalate", &sev
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	key := strings.Repeat("a", 64)
	oldID := "22222222-1111-4111-8111-111111111111"
	expiry := time.Now().Add(time.Minute)
	target := DispatchTarget{ReceiverID: "ops"}
	var entry Entry
	lost := false
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "lookup":
			if p["operation_id"] == oldID {
				record := actionIntent{Request: mustRaw(t, ordinaryRequest{Kind: "ordinary", OperationID: oldID, EpisodeRef: req.EpisodeRef, Target: target}), Digest: strings.Repeat("b", 64), Result: ActionResultV1{EpisodeRef: req.EpisodeRef, OperationID: oldID, PermitExpiresAt: &expiry, Targets: []TargetResult{{State: "pending", TargetKey: key, Target: target}}}}
				return json.Unmarshal(mustRaw(t, record), out)
			}
			if lost {
				return unavailable
			}
			return nil
		case "claim-target":
			return json.Unmarshal(mustRaw(t, map[string]any{"entry_token": key, "lease_expires_at": expiry, "permit_expires_at": expiry}), out)
		case "reserve":
			reason := "AWAITING_NATIVE_COMMIT"
			*out.(*ActionResultV1) = ActionResultV1{Reason: &reason}
			return nil
		case "commit":
			require.False(t, entry.Valid())
			lost = true
			return unavailable
		case "recover":
			// The initial read can overtake the ambiguous write and still see the old floor.
			*out.(**EpisodeProjection) = &EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", LifecycleSeq: 1, NativeVariant: variantOf(source)}}
			return nil
		default:
			t.Fatalf("unexpected %s", cmd)
			return nil
		}
	}), singleActionDispatch{target: target})
	o.lease = actionLease{Epoch: 1, ExpiresAt: expiry}
	o.recovered = true
	o.byID[req.EpisodeRef.EpisodeID] = &episodeSlot{source: source, projection: EpisodeProjection{episodeUpdate: episodeUpdate{EpisodeRef: req.EpisodeRef, State: "firing", SourceSeverity: "major", NativeVariant: variantOf(source), LifecycleSeq: 1}}}
	var err error
	entry, err = o.Claim(t.Context(), oldID, key)
	require.NoError(t, err)
	require.True(t, entry.Valid())
	_, err = o.Execute(t.Context(), req)
	require.Error(t, err)
	require.False(t, entry.Valid())
	_, err = o.Claim(t.Context(), oldID, key)
	require.Error(t, err)
}

func TestEntryExpiresDuringReadiness(t *testing.T) {
	deadline := time.Now().Add(20 * time.Millisecond)
	e := Entry{expires: deadline, valid: func() bool { <-time.After(time.Until(deadline)); return true }}
	require.False(t, e.Valid())
}

func TestOverflowGCAndDeferredRecoveryAtCapacity(t *testing.T) {
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	fp := source.Fingerprint().String()
	p := EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: defaultActionAuthority, EpisodeID: "22222222-1111-4111-8111-111111111111", Generation: 1, VariantRevision: 1}, LifecycleSeq: 1, NativeVariant: variantOf(source), State: "firing", SourceSeverity: "major", ActiveSince: source.StartsAt.UTC().Format(time.RFC3339Nano)}, Floor: "critical", SeverityRevision: 1}
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
		if cmd == "recover" {
			if args["projection"] == "episodes" {
				rows := []EpisodeProjection{}
				if args["after_id"] == nil {
					rows = append(rows, p)
				}
				*out.(*[]EpisodeProjection) = rows
				return nil
			}
			require.Equal(t, "source", args["projection"])
			require.Equal(t, fp, args["fingerprint"])
			*out.(*[]EpisodeProjection) = []EpisodeProjection{p}
			return nil
		}
		require.Equal(t, "project-episode", cmd)
		u := args["update"].(episodeUpdate)
		require.Equal(t, p.EpisodeRef, u.EpisodeRef)
		x := p
		x.episodeUpdate = u
		*out.(*EpisodeProjection) = x
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	churn := *source
	churn.Labels = model.LabelSet{"alertname": "churning"}
	key := sourceKey("", churn.Fingerprint().String())
	o.observe("", &churn, false)
	for n := 1; n < maxActionEpisodes; n++ {
		o.byKey[fmt.Sprint(n)] = &episodeSlot{}
	}
	require.NoError(t, o.recoverEpisodes(t.Context()))
	require.Len(t, o.byKey, maxActionEpisodes)
	s := o.slot(key, false)
	for n := 1; n <= maxTransitions*4; n++ {
		a := churn
		a.StartsAt = churn.StartsAt.Add(time.Duration(n))
		o.observe("", &a, false)
		if n == maxTransitions*4 {
			o.observe("", &a, true)
		}
	}
	require.True(t, s.overflow)
	require.Len(t, s.pending, maxTransitions)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Len(t, o.byKey, maxActionEpisodes-1)
	other := *source
	other.StartsAt = other.StartsAt.Add(time.Nanosecond)
	o.observe("", &other, false)
	_, err := o.Project(t.Context(), &other)
	require.ErrorIs(t, err, unverified)
	slot := o.slot(sourceKey("", fp), false)
	require.Equal(t, p.EpisodeRef, slot.projection.EpisodeRef)
	require.Equal(t, "critical", slot.projection.Floor)
	// GC retires the unmatched local pair. A later exact provider member recovers its floor.
	o.observe("", &other, true)
	o.sweepSlot(o.withEpoch(t.Context()), sourceKey("", fp), slot)
	require.Nil(t, o.slot(sourceKey("", fp), false))
	o.observe("", source, false)
	match, err := o.Project(t.Context(), source)
	require.NoError(t, err)
	require.Equal(t, p.EpisodeRef, match.EpisodeRef)
	require.Equal(t, "critical", match.Floor)
}

func TestPreparedOrdinaryLifecycleTakeoverAndGC(t *testing.T) {
	source := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: time.Now().Add(-time.Hour), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	var journal EpisodeProjection
	var attempts []uint64
	o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		switch cmd {
		case "project-episode":
			u := p["update"].(episodeUpdate)
			attempts = append(attempts, u.LifecycleSeq)
			if u.LifecycleSeq == 2 {
				return unavailable
			}
			require.Equal(t, journal.LifecycleSeq+1, u.LifecycleSeq)
			journal = EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: u}
			*out.(*EpisodeProjection) = journal
		case "recover":
			require.Equal(t, "episode", p["projection"])
			require.Equal(t, journal.EpisodeRef.EpisodeID, p["episode_id"])
			reply := journal
			*out.(**EpisodeProjection) = &reply
		default:
			t.Fatalf("unexpected command %s", cmd)
		}
		return nil
	}), testActionDispatch{})
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	o.recovered = true
	o.observe("", source, false)
	_, err := o.Project(t.Context(), source)
	require.NoError(t, err)
	key := sourceKey("", source.Fingerprint().String())
	s := o.slot(key, false)
	o.observe("", source, false)
	_, err = o.Project(t.Context(), source)
	require.Error(t, err)
	o.observe("", source, true)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Same(t, s, o.slot(key, false))
	require.NotNil(t, s.next)
	require.Equal(t, uint64(2), s.next.LifecycleSeq)
	// A different lease owner committed the prepared lifecycle and a subsequent
	// observation. Startup reattaches the later projection before draining GC.
	journal.LifecycleSeq = 3
	journal.Floor = "critical"
	journal.SeverityRevision = 1
	o.lease.Epoch = 3
	s.uncertain = true
	require.NoError(t, o.restoreEpisode(journal))
	before := len(attempts)
	o.sweepSlot(o.withEpoch(t.Context()), key, s)
	require.Nil(t, s.next)
	require.Nil(t, o.slot(key, false))
	require.Equal(t, []uint64{4}, attempts[before:])
	require.Equal(t, "resolved", journal.State)
}

func TestPreparedOrdinaryTakeoverRequiresExactLaterInterval(t *testing.T) {
	for _, mode := range []string{"old-resident", "exact-successor", "exact-closed", "reused-start"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			old := alert.New(model.Alert{Labels: model.LabelSet{"severity": "major"}, StartsAt: now.Add(-3 * time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
			var journal EpisodeProjection
			var writes []episodeUpdate
			o := newNativeActionOwner(defaultActionAuthority, actionRPCFunc(func(_ context.Context, cmd string, args map[string]any, out any) error {
				switch cmd {
				case "project-episode":
					u := args["update"].(episodeUpdate)
					writes = append(writes, u)
					if u.LifecycleSeq == 2 && u.EpisodeRef.Generation == 1 {
						return unavailable
					}
					journal = EpisodeProjection{ID: "11111111-1111-4111-8111-111111111111", episodeUpdate: u}
					*out.(*EpisodeProjection) = journal
				case "recover":
					require.Equal(t, "episode", args["projection"])
					require.Equal(t, journal.EpisodeRef.EpisodeID, args["episode_id"])
					row := journal
					*out.(**EpisodeProjection) = &row
				default:
					t.Fatalf("unexpected %s", cmd)
				}
				return nil
			}), testActionDispatch{})
			o.lease = actionLease{Epoch: 1, ExpiresAt: now.Add(time.Hour)}
			o.recovered = true
			o.observe("", old, false)
			_, err := o.Project(t.Context(), old)
			require.NoError(t, err)
			o.observe("", old, false)
			_, err = o.Project(t.Context(), old)
			require.Error(t, err)
			older := *old
			older.StartsAt = old.StartsAt.Add(time.Minute)
			o.observe("", old, false)
			o.observe("", &older, false)
			key := sourceKey("", old.Fingerprint().String())
			s := o.slot(key, false)
			require.Len(t, s.pending, 3)
			successor := *old
			successor.StartsAt = now.Add(-time.Hour)
			if mode == "reused-start" {
				successor.StartsAt = old.StartsAt
			}
			// A different owner closed the old generation and advanced the same
			// fingerprint. It also closed the successor in the reported failure.
			journal.ID = "22222222-2222-4222-8222-222222222222"
			journal.EpisodeRef.Generation++
			journal.LifecycleSeq = 2
			journal.NativeVariant = variantOf(&successor)
			journal.ActiveSince = journal.NativeVariant.StartsAt
			journal.State = "resolved"
			current := &older
			if mode != "old-resident" {
				journal.State = "firing"
				journal.LifecycleSeq = 1
				journal.Floor = "critical"
				journal.SeverityRevision = 1
				if mode == "exact-closed" {
					journal.State = "resolved"
					journal.Floor = ""
					successor.EndsAt = now.Add(-time.Minute)
				}
				current = &successor
				o.observe("", current, false)
			}
			o.lease.Epoch = 3
			s.uncertain = true
			if journal.State == "firing" {
				require.NoError(t, o.restoreEpisode(journal))
			}
			before := len(writes)
			p, err := o.Project(t.Context(), current)
			if mode == "exact-successor" || mode == "exact-closed" {
				require.NoError(t, err)
				require.Equal(t, journal.State, p.State)
				require.Equal(t, journal.EpisodeRef, p.EpisodeRef)
				require.Equal(t, journal.Floor, p.Floor)
				_, err = o.Project(t.Context(), old)
				require.Error(t, err)
			} else {
				require.ErrorIs(t, err, reconcile)
				o.sweepSlot(o.withEpoch(t.Context()), key, s)
				require.Same(t, s, o.slot(key, false))
				o.observe("", current, true)
				o.sweepSlot(o.withEpoch(t.Context()), key, s)
				require.Nil(t, o.slot(key, false))
			}
			require.Empty(t, writes[before:], "takeover replayed a buffered firing observation")
		})
	}
}
