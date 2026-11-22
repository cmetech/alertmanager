// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/prometheus/alertmanager/alert"
)

// OrdinaryCohortJournal admits only full-scope, firing contacts at one physical receiver integration.
type OrdinaryCohortJournal interface {
	AdmitCohort(context.Context, []OrdinaryCandidate) []OrdinaryAdmission
	SettleCohort(context.Context, []OrdinaryReceipt) error
	CohortReady() bool
	CohortSupported() bool
	InspectCohort(context.Context, []OrdinaryCandidate) []string
}

type OrdinaryCandidate struct {
	Canonical  bool
	Member     *alert.Alert
	Projection EpisodeProjection
	Target     DispatchTarget
}
type OrdinaryAdmission struct {
	Entry     Entry
	Delivery  alert.NativeDeliveryV1
	TargetKey string
	Covered   bool
	Err       error
}
type OrdinaryReceipt struct {
	Entry             Entry
	Outcome, Evidence string
}

const ordinaryChunk = 64

type cohortRequest struct {
	ID        string              `json:"operation_id"`
	Row       string              `json:"row_id"`
	Ref       EpisodeRef          `json:"ref"`
	Variant   alert.NativeVariant `json:"native_variant"`
	Target    DispatchTarget      `json:"target"`
	Revision  uint64              `json:"expected_revision"`
	Lifecycle uint64              `json:"lifecycle_seq"`
}
type cohortResult struct {
	ID       string         `json:"operation_id"`
	State    string         `json:"state"`
	Key      string         `json:"target_key"`
	Target   DispatchTarget `json:"target"`
	Token    string         `json:"entry_token"`
	Lease    time.Time      `json:"lease_expires_at"`
	Permit   time.Time      `json:"permit_expires_at"`
	Evidence string         `json:"evidence"`
}

type cohortChunk struct {
	begin, end int
	err        error
}

// Account for the complete RPC envelope and the JSON encoding of each target
// (including string escaping). Compute all boundaries before issuing a permit.
func (o *nativeActionOwner) cohortChunks(epoch uint64, requests []cohortRequest) []cohortChunk {
	envelope, _ := json.Marshal(map[string]any{"members": []cohortRequest{}, "authority_id": o.authority, "owner_id": o.owner, "epoch": epoch})
	start, size := 0, len(envelope)
	var chunks []cohortChunk
	for i, r := range requests {
		encoded, err := json.Marshal(r)
		if start < i && (i-start == ordinaryChunk || err != nil || size+1+len(encoded) > actionBodyLimit) {
			chunks = append(chunks, cohortChunk{begin: start, end: i})
			start, size = i, len(envelope)
		}
		if err != nil || len(envelope)+len(encoded) > actionBodyLimit {
			if err == nil {
				err = privateCommandTooLarge
			}
			chunks = append(chunks, cohortChunk{begin: i, end: i + 1, err: err})
			start, size = i+1, len(envelope)
			continue
		}
		if start < i {
			size++ // Comma between adjacent encoded members.
		}
		size += len(encoded)
	}
	if start < len(requests) {
		chunks = append(chunks, cohortChunk{begin: start, end: len(requests)})
	}
	return chunks
}

func (o *nativeActionOwner) CohortReady() bool {
	return o.CohortSupported() && o.ready()
}

// The provider publication owns this witness. It remains valid across mutable
// slot reclamation, including residents recovered without allocating a slot.
type cohortPublication interface {
	FreezeEpisode(*alert.Alert, EpisodeProjection) *atomic.Bool
}

func (o *nativeActionOwner) AdmitCohort(ctx context.Context, candidates []OrdinaryCandidate) []OrdinaryAdmission {
	ctx = o.withEpoch(ctx)
	out := make([]OrdinaryAdmission, len(candidates))
	var requests []cohortRequest
	var positions []int
	var stamps []*atomic.Bool
	pub, ok := o.dispatch.(cohortPublication)
	epoch, _ := PublicationToken(ctx)
	// Finish every potentially slow managed proof and plan before the first permit.
	for i, c := range candidates {
		out[i].Err = reconcile
		if !ok || c.Member == nil || c.Member.Resolved() || c.Projection.State != "firing" || len(c.Target.Scope) != 0 {
			continue
		}
		p, source := c.Projection, c.Member.ProviderSource()
		if !sameResident(p, source) || !managedUUID.MatchString(p.ID) {
			continue
		}
		stamp := pub.FreezeEpisode(source, p)
		if stamp == nil || o.verifySource(ctx, source, p.State) != nil {
			continue
		}
		targets, reason, err := o.dispatch.Plan(WithPersistedTarget(ctx, c.Target), source, p, ActionRequestV1{Kind: "ordinary", EpisodeRef: p.EpisodeRef, TargetScope: c.Target.Scope})
		if err != nil || reason != "" || !slices.ContainsFunc(targets, func(t DispatchTarget) bool { return reflect.DeepEqual(t, c.Target) }) {
			continue
		}
		requests = append(requests, cohortRequest{uuid.NewString(), p.ID, p.EpisodeRef, p.NativeVariant, c.Target, p.SeverityRevision, p.LifecycleSeq})
		positions = append(positions, i)
		stamps = append(stamps, stamp)
	}
	for _, part := range o.cohortChunks(epoch, requests) {
		start := part.begin
		if part.err != nil {
			out[positions[start]].Err = part.err
			continue
		}
		chunk := requests[start:part.end]
		if !o.CohortReady() || !o.live(ctx) {
			break
		}
		var rows []cohortResult
		err := o.write(ctx, "admit-cohort", map[string]any{"members": chunk}, &rows)
		if errors.Is(err, privateCommandTooLarge) {
			for i := range chunk {
				out[positions[start+i]].Err = err
			}
			continue
		}
		if err != nil || len(rows) != len(chunk) {
			// A lost claim reply cannot recreate the original random token. Only
			// inspect the submitted IDs; their entered coverage stays fenced.
			ids := make([]string, len(chunk))
			for n, item := range chunk {
				ids[n] = item.ID
			}
			known, readErr := o.lookupCohort(ctx, ids)
			for n, id := range ids {
				if readErr != nil || n >= len(known) || known[n].ID != id {
					continue
				}
				if known[n].State == "missing" {
					out[positions[start+n]].Err = unavailable
				}
				// Even an exact entered/unknown record lacks the original random
				// token. Keep the reconciliation hold in place in that case.
			}
		}
		var refused []OrdinaryReceipt
		for n, row := range rows {
			if n >= len(chunk) || row.ID != chunk[n].ID {
				continue
			}
			index := positions[start+n]
			c := candidates[index]
			if row.State == "covered" && err == nil && len(rows) == len(chunk) {
				out[index] = OrdinaryAdmission{Covered: true}
				continue
			}
			if row.State != "entered" || !managedHash.MatchString(row.Token) || !managedHash.MatchString(row.Key) {
				continue
			}
			stamp := stamps[start+n]
			expires := o.localDeadline(row.Permit)
			if lease := o.localDeadline(row.Lease); lease.Before(expires) {
				expires = lease
			}
			p := c.Projection
			e := claimedEntry{OperationID: row.ID, TargetKey: row.Key, token: row.Token, source: c.Member.ProviderSource(), severity: p.EffectiveSeverity(), ref: p.EpisodeRef, revision: p.SeverityRevision, target: c.Target, expires: expires, stamp: stamp, valid: func() bool {
				live, receipts := o.RecoveryState()
				return live == epoch && (!c.Canonical || receipts) && o.CohortSupported() && stamp.Load()
			}}
			id := uuid.NewSHA1(uuid.MustParse(row.ID), []byte(row.Key)).String()
			d := alert.NativeDeliveryV1{Version: 1, EpisodeRef: p.EpisodeRef, NativeVariant: p.NativeVariant, LifecycleSeq: p.LifecycleSeq, State: p.State, ActiveSince: p.ActiveSince, SourceSeverity: p.SourceSeverity, EffectiveSeverity: p.EffectiveSeverity(), DeliveryID: id, TargetScope: c.Target.Scope}
			if err != nil || len(rows) != len(chunk) || !e.ForMember(c.Member) || !e.LocalValid() || !reflect.DeepEqual(row.Target, c.Target) || c.Canonical && d.Validate(c.Target.ReceiverID) != nil {
				refused = append(refused, OrdinaryReceipt{e, "no_effect", "INVALIDATED_BEFORE_PROVIDER_ENTRY"})
				continue
			}
			out[index] = OrdinaryAdmission{Entry: e, TargetKey: row.Key, Delivery: d}
		}
		if len(refused) > 0 {
			_ = o.SettleCohort(ctx, refused)
		}
	}
	return out
}

func (o *nativeActionOwner) InspectCohort(ctx context.Context, members []OrdinaryCandidate) []string {
	ctx = o.withEpoch(ctx)
	states := make([]string, len(members))
	epoch, _ := PublicationToken(ctx)
	requests := make([]cohortRequest, 0, len(members))
	for _, c := range members {
		p := c.Projection
		requests = append(requests, cohortRequest{uuid.NewString(), p.ID, p.EpisodeRef, p.NativeVariant, c.Target, p.SeverityRevision, p.LifecycleSeq})
	}
	for _, part := range o.cohortChunks(epoch, requests) {
		if part.err != nil {
			continue
		}
		if !o.CohortReady() {
			break
		}
		chunk := requests[part.begin:part.end]
		var rows []cohortResult
		if o.write(ctx, "inspect-cohort", map[string]any{"members": chunk}, &rows) != nil || len(rows) != len(chunk) {
			continue
		}
		for n, row := range rows {
			if row.ID == chunk[n].ID {
				states[part.begin+n] = row.State
			}
		}
	}
	return states
}

func (o *nativeActionOwner) lookupCohort(ctx context.Context, ids []string) ([]cohortResult, error) {
	late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	var rows []cohortResult
	err := o.read(late, "lookup-cohort", map[string]any{"operation_ids": ids}, &rows)
	return rows, err
}

func (o *nativeActionOwner) SettleCohort(ctx context.Context, receipts []OrdinaryReceipt) error {
	var result error
	for chunk := range slices.Chunk(receipts, ordinaryChunk) {
		var payload []map[string]any
		var ids []string
		for _, r := range chunk {
			e, ok := r.Entry.(claimedEntry)
			if !ok {
				return conflict
			}
			ids = append(ids, e.OperationID)
			payload = append(payload, map[string]any{"operation_id": e.OperationID, "target_key": e.TargetKey, "entry_token": e.token, "receipt": map[string]string{"outcome": r.Outcome, "evidence": r.Evidence}})
		}
		late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		var settled []string
		err := o.read(late, "settle-cohort", map[string]any{"members": payload}, &settled)
		cancel()
		if err == nil && slices.Equal(ids, settled) {
			continue
		}
		rows, lookupErr := o.lookupCohort(ctx, ids)
		if lookupErr != nil || len(rows) != len(ids) {
			result = errors.Join(result, reconcile)
			continue
		}
		var retry []map[string]any
		var retryIDs []string
		for n, row := range rows {
			e := chunk[n].Entry.(claimedEntry)
			if row.ID != e.OperationID || row.Key != e.TargetKey {
				result = errors.Join(result, reconcile)
			} else if row.State == chunk[n].Outcome && row.Evidence == chunk[n].Evidence {
				continue
			} else if row.State == "entered" || row.State == "unknown" && chunk[n].Outcome != "unknown" {
				retry = append(retry, payload[n])
				retryIDs = append(retryIDs, e.OperationID)
			} else {
				result = errors.Join(result, reconcile)
			}
		}
		if len(retry) > 0 {
			// A current lookup proves the original token still has work. Replay
			// that same evidence once, irrespective of new-entry lease state.
			late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			var acknowledged []string
			err := o.read(late, "settle-cohort", map[string]any{"members": retry}, &acknowledged)
			cancel()
			if err != nil || !slices.Equal(acknowledged, retryIDs) {
				result = errors.Join(result, reconcile)
			}
		}
	}
	return result
}
