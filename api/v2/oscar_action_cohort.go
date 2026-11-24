// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/prometheus/alertmanager/alert"
)

// OrdinaryCohortJournal admits full-scope ordinary firing and terminal contacts at one physical receiver integration.
type OrdinaryCohortJournal interface {
	AdmitCohort(context.Context, []OrdinaryCandidate) []OrdinaryAdmission
	SettleCohort(context.Context, []OrdinaryReceipt) error
	CohortReady() bool
	CohortSupported() bool
	InspectCohort(context.Context, []OrdinaryCandidate) []string
}

type OrdinaryCandidate struct {
	Provenance *CallbackProvenance
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
	Completed bool
	// CoveredUntil is OSCAR's next_eligible for a covered row, mapped
	// conservatively to the local clock; zero when OSCAR did not return it.
	CoveredUntil time.Time
	Err          error
}
type OrdinaryReceipt struct {
	Entry             Entry
	Outcome, Evidence string
}

const ordinaryChunk = 64

type cohortRequest struct {
	Provenance *CallbackProvenance `json:"callback,omitempty"`
	ID         string              `json:"operation_id"`
	Row        string              `json:"row_id"`
	Ref        EpisodeRef          `json:"ref"`
	Variant    alert.NativeVariant `json:"native_variant"`
	Target     DispatchTarget      `json:"target"`
	Revision   uint64              `json:"expected_revision"`
	Lifecycle  uint64              `json:"lifecycle_seq"`
	Terminal   *cohortTerminal     `json:"terminal,omitempty"`
}
type cohortTerminal struct {
	SourceEndsAt time.Time `json:"source_ends_at"`
	SourceDigest string    `json:"source_digest"`
	WireResolved bool      `json:"wire_resolved"`
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
	// NextEligible is optional on covered rows (older stores omit it).
	NextEligible *time.Time `json:"next_eligible,omitempty"`
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

// Terminal requests must address the same UUIDv5 as the individual store path.
// The store independently derives this ID and verifies the complete frozen digest.
func (c OrdinaryCandidate) request() (cohortRequest, bool) {
	p, m := c.Projection, c.Member
	if m == nil || !managedUUID.MatchString(p.ID) || len(c.Target.Scope) != 0 || !sameResident(p, m.ProviderSource()) {
		return cohortRequest{}, false
	}
	r := cohortRequest{Row: p.ID, Ref: p.EpisodeRef, Variant: p.NativeVariant, Target: c.Target, Revision: p.SeverityRevision, Lifecycle: p.LifecycleSeq}
	switch p.State {
	case "firing":
		if m.Resolved() {
			return r, false
		}
		r.ID = uuid.NewString()
	case "resolved":
		source := m.ProviderSource()
		wireResolved := m.Resolved()
		if !terminalWireMatches(m, wireResolved) {
			return r, false
		}
		key, err := canonicalActionDigest([]any{c.Target.ReceiverID, c.Target.IntegrationDigest, []string{}})
		if err != nil {
			return r, false
		}
		r.ID = terminalOperationID(p, key)
		r.Terminal = &cohortTerminal{source.EndsAt.UTC(), terminalSourceDigest(source), wireResolved}
	default:
		return r, false
	}
	return r, true
}

func terminalOperationID(p EpisodeProjection, key string) string {
	return uuid.NewSHA1(uuid.MustParse(p.ID), []byte(fmt.Sprintf("terminal/%d/%d/%s", p.EpisodeRef.VariantRevision, p.LifecycleSeq, key))).String()
}

func (o *nativeActionOwner) AdmitCohort(ctx context.Context, candidates []OrdinaryCandidate) []OrdinaryAdmission {
	ctx = o.withEpoch(ctx)
	out := make([]OrdinaryAdmission, len(candidates))
	var requests []cohortRequest
	var positions []int
	stamps := make([]*atomic.Bool, len(candidates))
	pub, ok := o.dispatch.(cohortPublication)
	epoch, _ := PublicationToken(ctx)
	// Finish every potentially slow managed proof and plan before the first permit.
	for i, c := range candidates {
		out[i].Err = reconcile
		r, valid := c.request()
		if !ok || !valid {
			continue
		}
		p, source := c.Projection, c.Member.ProviderSource()
		stamp := pub.FreezeEpisode(source, p)
		if stamp == nil || o.verifySource(ctx, source, p.State) != nil {
			continue
		}
		targets, reason, err := o.dispatch.Plan(WithPersistedTarget(ctx, c.Target), source, p, ActionRequestV1{Kind: "ordinary", EpisodeRef: p.EpisodeRef, TargetScope: c.Target.Scope})
		if err != nil || reason != "" || !slices.ContainsFunc(targets, func(t DispatchTarget) bool { return reflect.DeepEqual(t, c.Target) }) {
			continue
		}
		r.Provenance = c.Provenance
		requests = append(requests, r)
		positions = append(positions, i)
		stamps[i] = stamp
	}
	for _, part := range o.cohortChunks(epoch, requests) {
		start := part.begin
		if part.err != nil {
			out[positions[start]].Err = part.err
			continue
		}
		if !o.CohortReady() || !o.live(ctx) {
			break
		}
		// Proof and planning for later members (or an earlier RPC) can outlive
		// this member's original wire state. Drop it before it acquires a token.
		chunk := make([]cohortRequest, 0, part.end-start)
		submitted := make([]int, 0, cap(chunk))
		for n := start; n < part.end; n++ {
			r, index := requests[n], positions[n]
			member := candidates[index].Member
			if !stamps[index].Load() {
				continue
			}
			if r.Terminal != nil {
				if !terminalWireMatches(member, r.Terminal.WireResolved) || !member.ProviderSource().EndsAt.Equal(r.Terminal.SourceEndsAt) {
					continue
				}
			} else if member.ProviderSource().Resolved() {
				continue
			}
			chunk = append(chunk, r)
			submitted = append(submitted, index)
		}
		if len(chunk) == 0 {
			continue
		}
		var rows []cohortResult
		err := o.write(ctx, "admit-cohort", map[string]any{"members": chunk}, &rows)
		if errors.Is(err, privateCommandTooLarge) {
			for i := range chunk {
				out[submitted[i]].Err = err
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
					out[submitted[n]].Err = unavailable
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
			index := submitted[n]
			c := candidates[index]
			terminal := chunk[n].Terminal
			if err == nil && len(rows) == len(chunk) && (terminal == nil && row.State == "covered" || terminal != nil && row.State == "completed") {
				if terminal == nil || stamps[index].Load() && o.live(ctx) && o.CohortSupported() && terminalWireMatches(c.Member, terminal.WireResolved) {
					out[index] = OrdinaryAdmission{Covered: row.State == "covered", Completed: row.State == "completed"}
					if row.State == "covered" && row.NextEligible != nil {
						out[index].CoveredUntil = o.conservativeDeadline(*row.NextEligible)
					}
				}
				continue
			}
			if row.State != "entered" || !managedHash.MatchString(row.Token) || !managedHash.MatchString(row.Key) {
				continue
			}
			stamp := stamps[index]
			expires := o.localDeadline(row.Permit)
			if lease := o.localDeadline(row.Lease); lease.Before(expires) {
				expires = lease
			}
			p := c.Projection
			e := claimedEntry{OperationID: row.ID, TargetKey: row.Key, token: row.Token, source: c.Member.ProviderSource(), severity: p.EffectiveSeverity(), ref: p.EpisodeRef, revision: p.SeverityRevision, target: c.Target, expires: expires, stamp: stamp, valid: func() bool {
				live, receipts := o.RecoveryState()
				return live == epoch && (!c.Canonical || receipts) && o.CohortSupported() && stamp.Load()
			}}
			if terminal != nil {
				e.terminal = &terminalObservation{terminal.WireResolved, terminal.SourceDigest, p.LifecycleSeq, p.NativeVariant, terminal.SourceEndsAt}
			}
			id := uuid.NewSHA1(uuid.MustParse(row.ID), []byte(row.Key)).String()
			d := alert.NativeDeliveryV1{Version: 1, EpisodeRef: p.EpisodeRef, NativeVariant: p.NativeVariant, LifecycleSeq: p.LifecycleSeq, State: p.State, ActiveSince: p.ActiveSince, SourceSeverity: p.SourceSeverity, EffectiveSeverity: p.EffectiveSeverity(), DeliveryID: id, TargetScope: c.Target.Scope}
			if err != nil || len(rows) != len(chunk) || terminal != nil && row.ID != terminalOperationID(p, row.Key) || !e.ForMember(c.Member) || !e.LocalValid() || !reflect.DeepEqual(row.Target, c.Target) || c.Canonical && d.Validate(c.Target.ReceiverID) != nil {
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
	var positions []int
	var stamps []*atomic.Bool
	pub, _ := o.dispatch.(cohortPublication)
	for i, c := range members {
		r, ok := c.request()
		if !ok {
			continue
		}
		var stamp *atomic.Bool
		if r.Terminal != nil {
			if pub == nil {
				continue
			}
			stamp = pub.FreezeEpisode(c.Member.ProviderSource(), c.Projection)
			if stamp == nil {
				continue
			}
		}
		stamps = append(stamps, stamp)
		requests = append(requests, r)
		positions = append(positions, i)
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
				if row.State == "completed" && chunk[n].Terminal == nil || row.State == "covered" && chunk[n].Terminal != nil {
					continue
				}
				index := positions[part.begin+n]
				m := members[index].Member
				if term := chunk[n].Terminal; term != nil && (!stamps[part.begin+n].Load() || !o.live(ctx) || !o.CohortSupported() || !terminalWireMatches(m, term.WireResolved)) {
					continue
				}
				states[index] = row.State
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
