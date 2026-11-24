// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/common/model"
)

type manualOwner struct {
	OwnerID         string  `json:"owner_id"`
	SourceEpisodeID string  `json:"source_episode_id"`
	SourceWorkID    string  `json:"source_work_id"`
	ClearActionID   *string `json:"clear_action_id"`
	Stamp           string  `json:"stamp"`
	Position        int64   `json:"position"`
}

type manualLocator struct {
	Work  string  `json:"work"`
	Clear *string `json:"clear"`
}

type manualPublication struct {
	OwnerID          string            `json:"owner_id"`
	SourceEpisodeID  string            `json:"source_episode_id"`
	NativeUUID       string            `json:"native_uuid"`
	Fingerprint      string            `json:"fingerprint"`
	SourceGeneration int64             `json:"source_generation"`
	Locator          manualLocator     `json:"locator"`
	Predecessor      *manualLocator    `json:"predecessor"`
	Position         int64             `json:"position"`
	Stamp            string            `json:"stamp"`
	Terminal         bool              `json:"terminal"`
	Payload          model.Alert       `json:"payload"`
	Projection       EpisodeProjection `json:"projection"`
}

type manualProvider interface {
	EnableManaged()
	ManagedApplied(string) (provider.ManagedStamp, bool)
	FinalizeManual(string, provider.ManagedStamp)
	ApplyManual(context.Context, string, *alert.Alert, provider.ManagedStamp, provider.ManagedStamp, bool, func() error) error
}

func (m manualPublication) stamp() provider.ManagedStamp {
	id := m.Locator.Work
	if m.Locator.Clear != nil {
		id = *m.Locator.Clear
	}
	return provider.ManagedStamp{Generation: m.Position, Attempt: id, Digest: m.Stamp}
}

func (m manualPublication) valid() bool {
	return managedHash.MatchString(m.OwnerID) && managedHash.MatchString(m.SourceEpisodeID) &&
		managedHash.MatchString(m.Locator.Work) && (m.Locator.Clear == nil || m.Terminal && managedHash.MatchString(*m.Locator.Clear)) &&
		m.Position > 0 && m.SourceGeneration > 0 && managedHash.MatchString(m.Stamp) && managedUUID.MatchString(m.NativeUUID) &&
		m.Payload.Labels.Fingerprint().String() == m.Fingerprint && !m.Payload.StartsAt.IsZero() && !m.Payload.EndsAt.Before(m.Payload.StartsAt)
}

func (m manualPublication) update(authority string, previous *manualPublication) (episodeUpdate, error) {
	if !m.valid() {
		return episodeUpdate{}, unverified
	}
	start := m.Payload.StartsAt.UTC().Format(time.RFC3339Nano)
	v := alert.NativeVariant{Fingerprint: m.Fingerprint, StartsAt: start}
	ref := EpisodeRef{AuthorityID: authority, EpisodeID: m.NativeUUID, Generation: 1, VariantRevision: 1}
	seq := uint64(1)
	if previous != nil {
		p := previous.Projection
		if !previous.valid() || m.Predecessor == nil || m.Predecessor.Work != previous.Locator.Work ||
			m.Predecessor.Clear != nil || previous.Locator.Clear != nil || previous.Terminal ||
			previous.OwnerID != m.OwnerID || previous.SourceEpisodeID != m.SourceEpisodeID ||
			previous.SourceGeneration != m.SourceGeneration || previous.Position+1 != m.Position ||
			!previous.Payload.StartsAt.Equal(m.Payload.StartsAt) || p.EpisodeRef.AuthorityID != authority ||
			p.EpisodeRef.EpisodeID != m.NativeUUID || p.ManualOwner == nil || p.ManualOwner.Stamp != previous.Stamp ||
			p.ManualOwner.SourceWorkID != previous.Locator.Work {
			return episodeUpdate{}, reconcile
		}
		ref = p.EpisodeRef
		if !sameVariant(v, p.NativeVariant) {
			ref.VariantRevision++
		}
		seq = p.LifecycleSeq + 1
	}
	state := "firing"
	if m.Terminal {
		state = "resolved"
	}
	return episodeUpdate{EpisodeRef: ref, NativeVariant: v, ActiveSince: start, LifecycleSeq: seq, State: state,
		SourceSeverity: string(m.Payload.Labels["severity"]), ManualOwner: &manualOwner{OwnerID: m.OwnerID, SourceEpisodeID: m.SourceEpisodeID, SourceWorkID: m.Locator.Work, ClearActionID: m.Locator.Clear, Position: m.Position, Stamp: m.Stamp}}, nil
}

func (o *nativeActionOwner) applyManual(ctx context.Context, m manualPublication, prior provider.ManagedStamp, restore bool) error {
	member := alert.New(m.Payload, time.Now(), false)
	member.EndTimeSource = alert.EndTimeSourceSender
	member.ManualEpisode, member.ManualStamp, member.ManualTerminal = m.SourceEpisodeID, m.Stamp, m.Terminal
	o.mu.Lock()
	lease := o.lease
	o.mu.Unlock()
	epoch, _ := ctx.Value(actionEpochKey{}).(uint64)
	// The local process never reuses an epoch. A changed owner must wait for
	// this shortened deadline. No remote or DB call inside SetBatch.
	return o.manual.ApplyManual(ctx, member.ActionOwner(), member, m.stamp(), prior, restore, func() error {
		o.mu.Lock()
		current := o.lease
		o.mu.Unlock()
		if !lease.currentEpoch(epoch) || !current.currentEpoch(epoch) || ctx.Err() != nil {
			return unavailable
		}
		return nil
	})
}

// enterManual reserves one active provider handoff for a stable manual source.
// The local map mutex is released before provider work or private store calls.
func (o *nativeActionOwner) enterManual(owner string) (func(), error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.manualInflight[owner] || len(o.manualInflight) >= o.maxEpisodes {
		return nil, unavailable
	}
	if o.manualInflight == nil {
		o.manualInflight = make(map[string]bool)
	}
	o.manualInflight[owner] = true
	return func() { o.mu.Lock(); delete(o.manualInflight, owner); o.mu.Unlock() }, nil
}

func (o *nativeActionOwner) pullManual(ctx context.Context) error {
	var claim *struct {
		Current  manualPublication
		Previous *manualPublication
	}
	if err := o.write(ctx, "claim-manual-source", map[string]any{}, &claim); err != nil || claim == nil {
		return err
	}
	m := claim.Current
	update, err := m.update(o.authority, claim.Previous)
	if err != nil {
		return err
	}
	release, err := o.enterManual(m.OwnerID)
	if err != nil {
		return err
	}
	defer release()
	var prior provider.ManagedStamp
	if p := claim.Previous; p != nil {
		prior = p.stamp()
		if _, ok := o.manual.ManagedApplied("u/" + m.SourceEpisodeID); !ok {
			if err = o.applyManual(ctx, *p, provider.ManagedStamp{}, true); err != nil {
				return err
			}
		}
	}
	if err = o.applyManual(ctx, m, prior, false); err != nil {
		return err
	}
	var committed EpisodeProjection
	if err = o.write(ctx, "project-episode", map[string]any{"update": update, "expected_seq": update.LifecycleSeq - 1}, &committed); err != nil {
		return err
	}
	if committed.ManualOwner == nil || committed.ManualOwner.Stamp != m.Stamp || committed.EpisodeRef != update.EpisodeRef || committed.State != update.State {
		return reconcile
	}
	if m.Terminal {
		o.manual.FinalizeManual("u/"+m.SourceEpisodeID, m.stamp())
	}
	return nil
}

func (o *nativeActionOwner) restoreManual(ctx context.Context, p EpisodeProjection) error {
	release, err := o.enterManual(p.ManualOwner.OwnerID)
	if err != nil {
		return err
	}
	defer release()
	// A resident stamp can be the unresolved next transition. The claimed
	// head reconciles it separately, without replaying the committed predecessor.
	if _, ok := o.manual.ManagedApplied("u/" + p.ManualOwner.SourceEpisodeID); ok {
		return nil
	}
	var m manualPublication
	if err := o.write(ctx, "restore-manual-source", map[string]any{"source_work_id": p.ManualOwner.SourceWorkID}, &m); err != nil {
		return err
	}
	if !m.valid() || m.OwnerID != p.ManualOwner.OwnerID || m.Stamp != p.ManualOwner.Stamp || m.NativeUUID != p.EpisodeRef.EpisodeID || m.Fingerprint != p.NativeVariant.Fingerprint {
		return unverified
	}
	return o.applyManual(ctx, m, provider.ManagedStamp{}, true)
}

func (o *nativeActionOwner) manualProjection(ctx context.Context, a *alert.Alert) (EpisodeProjection, error) {
	rows, err := o.sourceRows(ctx, a.ActionOwner(), a.Fingerprint().String())
	if err != nil {
		return EpisodeProjection{}, err
	}
	if len(rows) == 1 && sameResident(rows[0], a) {
		return rows[0], nil
	}
	if a.ManualTerminal {
		v := variantOf(a)
		var rows []EpisodeProjection
		if err = o.read(ctx, "recover", map[string]any{"projection": "terminal", "native_variant": v, "manual_key": a.ManualEpisode, "managed_key": nil, "managed_generation": nil}, &rows); err != nil {
			return EpisodeProjection{}, err
		}
		if len(rows) == 1 && sameResident(rows[0], a) {
			return rows[0], nil
		}
	}
	return EpisodeProjection{}, reconcile
}
