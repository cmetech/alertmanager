// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/prometheus/alertmanager/alert"
)

const defaultActionAuthority = "64171238-3cc5-448e-bd12-7502a062ec63"
const maxActionEpisodes = 4096
const maxTransitions = 16

var nativeFingerprint = regexp.MustCompile("^[0-9a-f]{16}$")

// ActionDispatch is implemented by the native notification pipeline in A4.
// Plan evaluates source and effective suppression and authorized routes. Publish
// installs an ordered projection. Wake schedules durable pending work by ID only.
// Neither Publish nor Wake may synchronously re-enter this episode's coordinator.
type ActionDispatch interface {
	Bind(ActionJournal) error
	Version() int
	Plan(context.Context, *alert.Alert, EpisodeProjection, ActionRequestV1) ([]DispatchTarget, string, error)
	Publish(context.Context, EpisodeProjection) error
	Wake(context.Context, string) error
}
type ActionOwnerConfig struct {
	Enabled                                                                   bool
	AuthorityID, Scheme, CAFile, StoreKeyFile, OperatorKeyFile, PolicyKeyFile string
	Dispatch                                                                  ActionDispatch
}
type actionRPC interface {
	call(context.Context, string, map[string]any, any) error
}
type actionClient struct{ *managedClient }

func (c actionClient) call(ctx context.Context, cmd string, args map[string]any, out any) error {
	b, err := json.Marshal(args)
	if err != nil || len(b) > actionBodyLimit {
		return conflict
	}
	r, err := http.NewRequestWithContext(ctx, "POST", c.scheme+"://alertmanager-middleware:9400/api/v1/internal/native-actions/"+cmd, bytes.NewReader(b))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(r)
	if err != nil {
		return unavailable
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil || len(raw) > 2<<20 {
		return unavailable
	}
	if resp.StatusCode != 200 {
		var e struct{ Detail string }
		if resp.StatusCode == 409 && json.Unmarshal(raw, &e) == nil && len(e.Detail) > 0 && len(e.Detail) <= 255 {
			return actionError{409, e.Detail}
		}
		return unavailable
	}
	if err = json.Unmarshal(raw, out); err != nil {
		return unavailable
	}
	return nil
}

type sourceOwner struct {
	EpisodeKey string `json:"episode_key"`
	Generation int64  `json:"generation"`
}
type episodeUpdate struct {
	EpisodeRef     EpisodeRef          `json:"episode_ref"`
	NativeVariant  alert.NativeVariant `json:"native_variant"`
	LifecycleSeq   uint64              `json:"lifecycle_seq"`
	ActiveSince    string              `json:"active_since"`
	State          string              `json:"state"`
	SourceSeverity string              `json:"source_severity"`
	ManagedOwner   *sourceOwner        `json:"managed_owner"`
}
type EpisodeProjection struct {
	PreviousEffective string `json:"-"`
	episodeUpdate
	ID               string `json:"id"`
	Floor            string `json:"floor"`
	SeverityRevision uint64 `json:"severity_revision"`
}

func (p EpisodeProjection) EffectiveSeverity() string {
	if firingRanks[p.Floor] > firingRanks[p.SourceSeverity] {
		return p.Floor
	}
	return p.SourceSeverity
}

type actionCommit struct {
	EpisodeRef       EpisodeRef       `json:"episode_ref"`
	SeverityRevision uint64           `json:"severity_revision"`
	Floor            *string          `json:"floor"`
	State            string           `json:"state"`
	Reason           *string          `json:"reason"`
	Targets          []DispatchTarget `json:"targets"`
}
type actionIntent struct {
	Request                json.RawMessage `json:"request"`
	Digest                 string          `json:"digest"`
	Intent                 *actionCommit   `json:"intent"`
	LogicalActionID        string          `json:"logical_action_id"`
	SupersedesOperationID  *string         `json:"supersedes_operation_id"`
	ReservationSuccessorID *string         `json:"reservation_successor_id"`
	Result                 ActionResultV1  `json:"result"`
}
type actionLease struct {
	TerminalObservations int       `json:"terminal_observations"`
	Protocol             string    `json:"protocol"`
	RecoverySelectors    int       `json:"recovery_selectors"`
	AuthorityID          string    `json:"authority_id"`
	OwnerID              string    `json:"owner_id"`
	Epoch                uint64    `json:"epoch"`
	ExpiresAt            time.Time `json:"expires_at"`
	RenewSeconds         int       `json:"renew_seconds"`
}
type actionEvent struct {
	source *alert.Alert
	closed bool
}
type pendingFloor struct {
	operationID, digest string
	update              actionCommit
	epoch               uint64
}
type episodeSlot struct {
	turn         sync.Mutex // All journal commands for this episode, never acquired by the provider.
	local        sync.Mutex // The provider only updates this bounded in-memory queue.
	source       *alert.Alert
	pending      []actionEvent
	publication  uint64
	observed     uint64
	removed      bool
	overflow     bool
	ambiguous    bool
	detached     bool
	needsRestore bool // Protected by turn after construction.
	nextEpoch    uint64
	projection   EpisodeProjection // Protected by turn.
	next         *episodeUpdate    // Keep the exact first assignment across ambiguous project replies.
	needsPublish bool
	uncertain    bool
	floorWrite   *pendingFloor
}
type nativeActionOwner struct {
	readSource            func(string, string, func(*alert.Alert))
	lockManaged           func(string) (func(), error)
	verifyManaged         func(context.Context, *alert.Alert, string) error
	callbackReady         func() bool
	authority, owner      string
	rpc                   actionRPC
	dispatch              ActionDispatch
	mu                    sync.Mutex // Short map/lease accesses only.
	byKey                 map[string]*episodeSlot
	byID                  map[string]*episodeSlot
	dbAnchor, localAnchor time.Time
	lease                 actionLease
	recovered             bool
	enrollments           uint64
	terminalMembership    [1 << 16]uint64
	bootCursor            struct {
		epoch                 uint64
		activeAfter, keyAfter string
		activeDone, keysDone  bool
	} // Owned by the single recovery loop.
	membership       [1 << 16]uint64  // Conservative per-owner recovery index; collisions require an indexed source lookup.
	untracked        map[string]uint8 // Entered direct contacts fence enrollment until conclusive settlement.
	deferredRecovery bool             // An omitted durable source must be checked on later enrollment.
	slots            chan struct{}
}

func newNativeActionOwner(authority string, rpc actionRPC, d ActionDispatch) *nativeActionOwner {
	return &nativeActionOwner{
		authority: authority, owner: uuid.NewString(), rpc: rpc, dispatch: d,
		untracked: make(map[string]uint8), byKey: map[string]*episodeSlot{}, byID: map[string]*episodeSlot{}, slots: make(chan struct{}, 32),
	}
}
func variantOf(a *alert.Alert) alert.NativeVariant {
	return alert.NativeVariant{Fingerprint: a.Fingerprint().String(), StartsAt: a.StartsAt.UTC().Format(time.RFC3339Nano)}
}
func sourceKey(owner, fp string) string {
	if owner != "" {
		return "m/" + owner
	}
	return "n/" + fp
}
func (o *nativeActionOwner) slot(key string, create bool) *episodeSlot {
	o.mu.Lock()
	defer o.mu.Unlock()
	s := o.byKey[key]
	if s == nil && create && len(o.byKey) < maxActionEpisodes && o.untracked[key] == 0 {
		bucket, bit := membershipBit(key)
		o.membership[bucket] |= bit
		o.enrollments++
		s = &episodeSlot{needsRestore: o.deferredRecovery}
		o.byKey[key] = s
	}
	return s
}
func sameVariant(x, y alert.NativeVariant) bool {
	if x.Fingerprint != y.Fingerprint {
		return false
	}
	a, e := time.Parse(time.RFC3339Nano, x.StartsAt)
	b, f := time.Parse(time.RFC3339Nano, y.StartsAt)
	return e == nil && f == nil && a.Equal(b)
}
func laterOrdinaryVariant(current, previous alert.NativeVariant) bool {
	if current.Fingerprint != previous.Fingerprint {
		return false
	}
	currentStart, err := time.Parse(time.RFC3339Nano, current.StartsAt)
	previousStart, previousErr := time.Parse(time.RFC3339Nano, previous.StartsAt)
	return err == nil && previousErr == nil && currentStart.After(previousStart)
}

func (o *nativeActionOwner) observe(owner string, source *alert.Alert, closed bool) {
	if source == nil && owner == "" {
		return
	}
	fp := ""
	if source != nil {
		fp = source.Fingerprint().String()
	}
	s := o.slot(sourceKey(owner, fp), o.readSource == nil && source != nil && !closed)
	if s == nil {
		return
	}
	s.local.Lock()
	defer s.local.Unlock()
	if s.detached {
		return
	}
	if source == nil {
		source = s.source
	}
	if source == nil {
		return
	}
	// A retired member's GC cannot close its replacement.
	if closed && s.source != nil && (s.source.Fingerprint() != source.Fingerprint() || !s.source.StartsAt.Equal(source.StartsAt) || s.source.ManagedMember != source.ManagedMember) {
		return
	}
	if s.source != nil && owner == "" && !source.StartsAt.Equal(s.source.StartsAt) && s.source.Resolved() && !s.source.EndsAt.After(source.StartsAt) && len(s.pending) < maxTransitions {
		s.pending = append(s.pending, actionEvent{s.source, true})
	}
	s.observed++
	s.removed = closed
	s.source = source
	event := actionEvent{source, closed || source.Resolved() || source.ManagedOperationKind == "clear"}
	if n := len(s.pending); n > 1 {
		last := s.pending[n-1]
		if last.closed == event.closed && last.source.Fingerprint() == source.Fingerprint() && last.source.StartsAt.Equal(source.StartsAt) && last.source.ManagedMember == source.ManagedMember {
			s.pending[n-1] = event
			return
		}
	}
	if len(s.pending) >= maxTransitions {
		s.overflow = true
		return
	}
	s.pending = append(s.pending, event)
}
func (o *nativeActionOwner) ready() bool {
	o.mu.Lock()
	ready := o.recovered && o.lease.ExpiresAt.After(time.Now())
	o.mu.Unlock()
	return ready && o.dispatch != nil && o.dispatch.Version() == 1 && (o.callbackReady == nil || o.callbackReady())
}
func (o *nativeActionOwner) read(ctx context.Context, cmd string, p map[string]any, out any) error {
	p["authority_id"] = o.authority
	return o.rpc.call(ctx, cmd, p, out)
}

type actionEpochKey struct{}

func (o *nativeActionOwner) withEpoch(ctx context.Context) context.Context {
	if ctx.Value(actionEpochKey{}) != nil {
		return ctx
	}
	o.mu.Lock()
	epoch := o.lease.Epoch
	o.mu.Unlock()
	return context.WithValue(ctx, actionEpochKey{}, epoch)
}
func (o *nativeActionOwner) live(ctx context.Context) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	epoch, _ := ctx.Value(actionEpochKey{}).(uint64)
	return epoch != 0 && o.recovered && epoch == o.lease.Epoch && time.Now().Before(o.lease.ExpiresAt)
}
func (o *nativeActionOwner) write(ctx context.Context, cmd string, p map[string]any, out any) error {
	if ctx.Err() != nil {
		return unavailable
	}
	o.mu.Lock()
	lease := o.lease
	o.mu.Unlock()
	if pinned, ok := ctx.Value(actionEpochKey{}).(uint64); !ok || pinned != lease.Epoch || !lease.ExpiresAt.After(time.Now()) {
		return unavailable
	}
	p["owner_id"], p["epoch"] = o.owner, lease.Epoch
	err := o.read(ctx, cmd, p, out)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.lease.Epoch != lease.Epoch || !lease.ExpiresAt.After(time.Now()) {
		return unavailable
	}
	return nil
}
func (o *nativeActionOwner) projectionKey(p EpisodeProjection) (string, error) {
	if !validRef(p.EpisodeRef) || p.EpisodeRef.AuthorityID != o.authority || (p.State != "firing" && p.State != "resolved") || p.LifecycleSeq == 0 || (firingRanks[p.SourceSeverity] == 0 && !(p.State == "resolved" && p.SourceSeverity == "cleared")) || p.Floor != "" && firingRanks[p.Floor] == 0 || !nativeFingerprint.MatchString(p.NativeVariant.Fingerprint) {
		return "", unavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, p.NativeVariant.StartsAt); err != nil {
		return "", unavailable
	}
	if _, err := time.Parse(time.RFC3339Nano, p.ActiveSince); err != nil {
		return "", unavailable
	}
	key := ""
	if p.ManagedOwner != nil {
		if !managedHash.MatchString(p.ManagedOwner.EpisodeKey) || p.ManagedOwner.Generation <= 0 {
			return "", unavailable
		}
		key = p.ManagedOwner.EpisodeKey
	}
	return key, nil
}

func (o *nativeActionOwner) restoreEpisode(p EpisodeProjection) error {
	key, err := o.projectionKey(p)
	if err != nil {
		return err
	}
	slotKey := sourceKey(key, p.NativeVariant.Fingerprint)
	bucket, bit := membershipBit(slotKey)
	o.mu.Lock()
	o.membership[bucket] |= bit
	o.mu.Unlock()
	s := o.slot(slotKey, false)
	if o.readSource != nil {
		o.readSource(key, p.NativeVariant.Fingerprint, func(a *alert.Alert) {
			if s == nil {
				s = o.slot(slotKey, true)
			}
			if s != nil && s.latest() == nil {
				o.observe(key, a, false)
			}
		})
	} else if s == nil {
		s = o.slot(slotKey, true)
	}
	if s == nil {
		// A missing resident or a full cache cannot prevent recovery of the other
		// rows. Later enrollment must consult the durable source candidates.
		o.mu.Lock()
		o.deferredRecovery = true
		o.mu.Unlock()
		return nil
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	s.local.Lock()
	detached := s.detached
	s.local.Unlock()
	if detached {
		return nil
	}
	if old := s.projection; old.ID == p.ID && old.ID != "" && (old.LifecycleSeq > p.LifecycleSeq || old.LifecycleSeq == p.LifecycleSeq && old.SeverityRevision > p.SeverityRevision) {
		return nil
	}
	if old := s.projection; old.ID != "" && old.ID != p.ID {
		if s.next != nil && s.next.ManagedOwner == nil && p.ManagedOwner == nil && old.ManagedOwner == nil &&
			old.EpisodeRef.EpisodeID == p.EpisodeRef.EpisodeID && s.next.EpisodeRef.EpisodeID == p.EpisodeRef.EpisodeID &&
			p.EpisodeRef.Generation > old.EpisodeRef.Generation {
			// A new generation has its own row. The prepared write needs the
			// exact UUID lookup and resident interval check after this boot scan.
			return nil
		}
		// Contradictory restored bindings quarantine this source without stopping other episodes.
		s.local.Lock()
		s.ambiguous = true
		s.local.Unlock()
		return nil
	}
	s.projection = p
	o.mu.Lock()
	s.needsRestore = o.deferredRecovery
	o.byID[p.EpisodeRef.EpisodeID] = s
	o.mu.Unlock()
	return nil
}
func sourceSeverity(a *alert.Alert, state string) string {
	sev := strings.ToLower(string(a.Labels["severity"]))
	if strings.TrimSpace(sev) == "" {
		if state == "resolved" {
			return "cleared"
		}
		return "major"
	}
	return sev
}
func (o *nativeActionOwner) nextUpdate(prev EpisodeProjection, e actionEvent) (episodeUpdate, error) {
	a := e.source
	u := prev.episodeUpdate
	v := variantOf(a)
	state := "firing"
	if e.closed {
		state = "resolved"
	}
	severity := sourceSeverity(a, state)
	if firingRanks[severity] == 0 && !(severity == "cleared" && state == "resolved") {
		return u, unverified
	}
	var m *sourceOwner
	if a.ManagedReceiver {
		member := a.ManagedMember
		if !managedHash.MatchString(member.Episode) || member.Generation <= 0 || !managedUUID.MatchString(member.Event) || !managedHash.MatchString(member.Digest) || a.ManagedOperationKind != "raise" && a.ManagedOperationKind != "update" && a.ManagedOperationKind != "clear" {
			return u, unverified
		}
		m = &sourceOwner{member.Episode, member.Generation}
	}
	if u.LifecycleSeq == 0 {
		u = episodeUpdate{EpisodeRef: EpisodeRef{AuthorityID: o.authority, EpisodeID: uuid.NewString(), Generation: 1, VariantRevision: 1}, NativeVariant: v, ActiveSince: v.StartsAt}
	} else if !sameVariant(u.NativeVariant, v) || !reflect.DeepEqual(m, u.ManagedOwner) {
		if m != nil && u.ManagedOwner != nil && m.EpisodeKey == u.ManagedOwner.EpisodeKey && m.Generation > u.ManagedOwner.Generation && u.State == "firing" {
			u.EpisodeRef.VariantRevision++
			u.NativeVariant = v
		} else if u.State == "resolved" && state == "firing" {
			if m == nil && (u.ManagedOwner != nil || !laterOrdinaryVariant(v, u.NativeVariant)) {
				return u, unverified
			}
			u.EpisodeRef.Generation++
			u.EpisodeRef.VariantRevision = 1
			u.NativeVariant = v
			u.ActiveSince = v.StartsAt
			u.LifecycleSeq = 0
		} else {
			return u, unverified
		}
	} else if u.State == "resolved" {
		if state == "resolved" {
			return u, nil
		}
		return u, reconcile
	} else {
		severity = u.SourceSeverity
	}
	u.State, u.ManagedOwner, u.SourceSeverity = state, m, severity
	u.LifecycleSeq++
	return u, nil
}

func (o *nativeActionOwner) rememberTerminal(p EpisodeProjection) error {
	owner, err := o.projectionKey(p)
	if err != nil || p.State != "resolved" {
		return reconcile
	}
	bucket, bit := membershipBit(sourceKey(owner, p.NativeVariant.Fingerprint))
	o.mu.Lock()
	o.terminalMembership[bucket] |= bit
	o.mu.Unlock()
	return nil
}

// terminalCandidate uses membership only to select an indexed read. Exact lifecycle and managed
// identity decide whether the result can be restored. A firing lookalike cannot reopen it.
func (o *nativeActionOwner) terminalCandidate(ctx context.Context, a *alert.Alert) (*EpisodeProjection, error) {
	v, owner := variantOf(a), a.ManagedMember.Episode
	bucket, bit := membershipBit(sourceKey(owner, v.Fingerprint))
	o.mu.Lock()
	possible := o.terminalMembership[bucket]&bit != 0
	o.mu.Unlock()
	if !possible {
		return nil, nil
	}
	var key, generation any
	if owner != "" {
		key, generation = owner, a.ManagedMember.Generation
	}
	var rows []EpisodeProjection
	if err := o.read(ctx, "recover", map[string]any{"projection": "terminal", "native_variant": v, "managed_key": key, "managed_generation": generation}, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > 1 {
		return nil, reconcile
	}
	if len(rows) == 0 {
		return nil, nil
	}
	p := rows[0]
	k, err := o.projectionKey(p)
	if err != nil || k != owner || !managedUUID.MatchString(p.ID) || p.State != "resolved" || !sameVariant(v, p.NativeVariant) ||
		p.ManagedOwner != nil && p.ManagedOwner.Generation != a.ManagedMember.Generation ||
		!a.Resolved() && !(a.ManagedReceiver && a.ManagedOperationKind == "clear") {
		return nil, reconcile
	}
	return &p, nil
}

// hydrate loads only the current durable candidates for a source skipped by a bounded recovery scan.
func (o *nativeActionOwner) hydrate(ctx context.Context, s *episodeSlot) error {
	a := s.latest()
	if a != nil && s.projection.ID == "" {
		p, err := o.terminalCandidate(ctx, a)
		if err != nil {
			return err
		}
		if p != nil {
			s.projection = *p
			o.mu.Lock()
			o.byID[p.EpisodeRef.EpisodeID] = s
			o.mu.Unlock()
		}
	}
	if !s.needsRestore {
		return nil
	}
	if a == nil {
		return unverified
	}
	var managed any
	key := a.ManagedMember.Episode
	if key != "" {
		managed = key
	}
	fp := a.Fingerprint().String()
	var rows []EpisodeProjection
	if err := o.read(ctx, "recover", map[string]any{"projection": "source", "managed_key": managed, "fingerprint": fp}, &rows); err != nil {
		return err
	}
	if rows == nil || len(rows) > 2 {
		return unavailable
	}
	if len(rows) == 2 || len(rows) == 1 && s.projection.ID != "" && s.projection.ID != rows[0].ID {
		s.local.Lock()
		s.ambiguous = true
		s.local.Unlock()
		return reconcile
	}
	if len(rows) == 1 {
		p := rows[0]
		owner, err := o.projectionKey(p)
		if err != nil || p.State != "firing" || !managedUUID.MatchString(p.ID) || owner != key || key == "" && p.NativeVariant.Fingerprint != fp {
			return reconcile
		}
		s.projection = p
		o.mu.Lock()
		o.byID[p.EpisodeRef.EpisodeID] = s
		o.mu.Unlock()
	}
	s.needsRestore = false
	return nil
}

// An expired epoch cannot finish a prepared CAS. A durable lifecycle at or beyond its
// sequence already covers the head observation, including when another owner wrote it.
func (o *nativeActionOwner) recoverPrepared(ctx context.Context, s *episodeSlot) error {
	next := s.next
	epoch, _ := ctx.Value(actionEpochKey{}).(uint64)
	if next == nil || epoch == s.nextEpoch {
		return nil
	}
	if !o.live(ctx) {
		return unavailable
	}
	var stored *EpisodeProjection
	if err := o.read(ctx, "recover", map[string]any{"projection": "episode", "episode_id": next.EpisodeRef.EpisodeID}, &stored); err != nil {
		return err
	}
	if !o.live(ctx) {
		return unavailable
	}
	if stored == nil {
		// An uncommitted first assignment can lose its UUID to a succeeding
		// owner. Re-evaluate this observation against the scoped durable index.
		if next.LifecycleSeq != 1 || s.projection.EpisodeRef.EpisodeID == next.EpisodeRef.EpisodeID {
			return reconcile
		}
		s.next = nil
		s.needsRestore = true
		return nil
	}
	key, err := o.projectionKey(*stored)
	if err != nil || !managedUUID.MatchString(stored.ID) || stored.EpisodeRef.EpisodeID != next.EpisodeRef.EpisodeID {
		return reconcile
	}
	sameGeneration := stored.EpisodeRef.Generation == next.EpisodeRef.Generation
	if stored.EpisodeRef.Generation < next.EpisodeRef.Generation || sameGeneration && stored.LifecycleSeq < next.LifecycleSeq {
		return nil
	}
	local := s.projection
	if local.LifecycleSeq > 0 && (local.EpisodeRef.EpisodeID != stored.EpisodeRef.EpisodeID || local.EpisodeRef.Generation > stored.EpisodeRef.Generation) {
		return reconcile
	}
	if local.EpisodeRef.Generation == stored.EpisodeRef.Generation && (local.ID != stored.ID || local.LifecycleSeq > stored.LifecycleSeq) {
		return reconcile
	}
	expectedOwner := ""
	if next.ManagedOwner != nil {
		expectedOwner = next.ManagedOwner.EpisodeKey
	}
	sameSource := sourceKey(key, stored.NativeVariant.Fingerprint) == sourceKey(expectedOwner, next.NativeVariant.Fingerprint)
	s.local.Lock()
	if len(s.pending) == 0 {
		s.local.Unlock()
		return reconcile
	}
	s.pending = s.pending[1:]
	s.publication++
	s.next = nil
	if next.ManagedOwner == nil && key == "" {
		if sameGeneration {
			sameSource = stored.EpisodeRef == next.EpisodeRef && sameVariant(stored.NativeVariant, next.NativeVariant)
		} else {
			// None of the queued events carried this newer generation. Rebuild
			// only from the last provider observation, and only for its exact pair.
			s.pending = nil
			resident := s.source
			sameSource = laterOrdinaryVariant(stored.NativeVariant, next.NativeVariant) &&
				stored.EpisodeRef.VariantRevision == 1 && resident != nil && !resident.ManagedReceiver && sameVariant(stored.NativeVariant, variantOf(resident))
			if sameSource {
				ended := s.removed || resident.Resolved()
				if stored.State == "resolved" {
					sameSource = ended
				} else if ended {
					s.pending = []actionEvent{{source: resident, closed: true}}
				}
			}
			if f := s.floorWrite; f != nil && f.epoch != epoch && f.update.EpisodeRef.EpisodeID == stored.EpisodeRef.EpisodeID && f.update.EpisodeRef.Generation < stored.EpisodeRef.Generation {
				s.floorWrite = nil
			}
		}
	}
	if !sameSource {
		// The old CAS has ended, but this slot cannot adopt a different source. GC
		// may reclaim the local quarantine without changing the durable successor.
		s.ambiguous = true
		s.local.Unlock()
		return reconcile
	}
	s.local.Unlock()
	s.projection = *stored
	s.needsPublish = true
	o.mu.Lock()
	o.byID[stored.EpisodeRef.EpisodeID] = s
	o.mu.Unlock()
	return nil
}

type sameFloorRetry struct{}

func floorCASPossible(p EpisodeProjection, u actionCommit) bool {
	return p.EpisodeRef == u.EpisodeRef && p.State == "firing" && p.SeverityRevision < u.SeverityRevision
}

func (o *nativeActionOwner) flush(ctx context.Context, s *episodeSlot) error {
	if source := s.latest(); source != nil && source.ManagedReceiver && o.lockManaged != nil {
		release, err := o.lockManaged(source.ManagedMember.Episode)
		if err != nil {
			return unavailable
		}
		defer release()
	}
	s.local.Lock()
	detached := s.detached
	s.local.Unlock()
	if detached {
		return unverified
	}
	if err := o.recoverPrepared(ctx, s); err != nil {
		return err
	}
	if err := o.hydrate(ctx, s); err != nil {
		return err
	}
	if s.uncertain {
		var current *EpisodeProjection
		ref := s.projection.EpisodeRef
		if err := o.read(ctx, "recover", map[string]any{"projection": "episode", "episode_id": ref.EpisodeID}, &current); err != nil {
			return err
		}
		if current == nil || current.EpisodeRef != ref || current.LifecycleSeq < s.projection.LifecycleSeq || !sameVariant(current.NativeVariant, s.projection.NativeVariant) || (current.LifecycleSeq != s.projection.LifecycleSeq && current.State != "resolved") {
			return reconcile
		}
		s.uncertain = false
		if f := s.floorWrite; f != nil {
			s.uncertain = ctx.Value(actionEpochKey{}) == f.epoch && floorCASPossible(*current, f.update)
			if !s.uncertain {
				s.floorWrite = nil
			}
		}
		s.projection = *current
		s.needsPublish = true
	}
	for i := 0; i <= maxTransitions; i++ {
		s.local.Lock()
		if s.detached || s.ambiguous || s.overflow && len(s.pending) == 0 {
			s.local.Unlock()
			return reconcile
		}
		if i == 0 && len(s.pending) == 0 && s.source != nil && s.projection.State == "firing" && s.source.Resolved() {
			s.pending = append(s.pending, actionEvent{s.source, true})
		}
		if len(s.pending) == 0 {
			s.local.Unlock()
			// A stale read can overtake the original floor write. Only its exact
			// authenticated retry may proceed while the old CAS could still commit.
			if f := s.floorWrite; f != nil && floorCASPossible(s.projection, f.update) && ctx.Value(sameFloorRetry{}) != f.operationID {
				return reconcile
			}
			return nil
		}
		event := s.pending[0]
		s.local.Unlock()
		logical := "firing"
		if event.closed {
			logical = "resolved"
		}
		proof := o.verifySource(ctx, event.source, logical)
		var closure closedManagedOwner
		closed := errors.As(proof, &closure)
		if proof != nil && !closed && !errors.Is(proof, discardedManagedMember) {
			return proof
		}
		var p EpisodeProjection
		if s.next != nil && proof != nil {
			// An earlier project may already have committed. Recover its exact lifecycle
			// before handling a cancelled observation or a later authoritative closure.
			var stored *EpisodeProjection
			if err := o.read(ctx, "recover", map[string]any{"projection": "episode", "episode_id": s.next.EpisodeRef.EpisodeID}, &stored); err != nil {
				return err
			}
			if stored != nil && stored.EpisodeRef == s.next.EpisodeRef && stored.LifecycleSeq == s.next.LifecycleSeq && stored.State == s.next.State && sameVariant(stored.NativeVariant, s.next.NativeVariant) {
				p = *stored
			} else if closed && s.next.State == "resolved" && s.next.ManagedOwner != nil && s.next.ManagedOwner.EpisodeKey == closure.key && s.next.ManagedOwner.Generation < closure.generation {
				// This exact prepared closure is still authoritatively fenced.
			} else if epoch, _ := ctx.Value(actionEpochKey{}).(uint64); epoch == s.nextEpoch {
				return reconcile
			} else {
				s.next = nil
			}
		}
		if s.next == nil {
			if closed {
				prev := s.projection
				if prev.ManagedOwner != nil && prev.ManagedOwner.EpisodeKey == closure.key && prev.ManagedOwner.Generation < closure.generation && prev.State == "firing" {
					u := prev.episodeUpdate
					u.State = "resolved"
					u.LifecycleSeq++
					s.next = &u
				}
			} else if proof == nil {
				next, err := o.nextUpdate(s.projection, event)
				if err != nil {
					return err
				}
				s.next = &next
			}
			if s.next == nil {
				s.local.Lock()
				s.pending = s.pending[1:]
				s.local.Unlock()
				continue
			}
			s.nextEpoch, _ = ctx.Value(actionEpochKey{}).(uint64)
		}
		recheckClosure := p.LifecycleSeq != 0 && p.State == "firing" && closed
		next := *s.next
		if p.LifecycleSeq == 0 {
			s.nextEpoch, _ = ctx.Value(actionEpochKey{}).(uint64)
			if err := o.write(ctx, "project-episode", map[string]any{"update": next, "expected_seq": next.LifecycleSeq - 1}, &p); err != nil {
				return err
			}
		}
		if p.EpisodeRef != next.EpisodeRef || p.State != next.State || p.LifecycleSeq != next.LifecycleSeq || !sameVariant(p.NativeVariant, next.NativeVariant) {
			return reconcile
		}
		s.local.Lock()
		s.publication++
		s.local.Unlock()
		if p.State == "resolved" {
			if err := o.rememberTerminal(p); err != nil {
				return err
			}
		}
		s.projection = p
		s.needsPublish = true
		s.next = nil
		if f := s.floorWrite; f != nil && !floorCASPossible(p, f.update) {
			s.floorWrite = nil
		}
		s.uncertain = s.floorWrite != nil
		o.mu.Lock()
		o.byID[p.EpisodeRef.EpisodeID] = s
		o.mu.Unlock()
		s.local.Lock()
		if !recheckClosure {
			s.pending = s.pending[1:]
		}
		s.local.Unlock()
	}
	return unavailable
}
func (s *episodeSlot) current(p EpisodeProjection, source *alert.Alert, active bool) error {
	s.local.Lock()
	defer s.local.Unlock()
	return s.currentLocked(p, source, active)
}
func (s *episodeSlot) currentLocked(p EpisodeProjection, source *alert.Alert, active bool) error {
	if s.detached || s.overflow || s.ambiguous {
		return reconcile
	}
	if len(s.pending) > 0 {
		return mismatch
	}
	if s.source == nil || s.source != source || !sameVariant(p.NativeVariant, variantOf(source)) {
		return unverified
	}
	if active && (p.State != "firing" || source.Resolved() || source.ManagedOperationKind == "clear") {
		return resolved
	}
	return nil
}
func (s *episodeSlot) latest() *alert.Alert { s.local.Lock(); defer s.local.Unlock(); return s.source }

// Project returns a journaled lifecycle for the exact current provider member.
// Every tracked ordinary dispatch and signed callback must pass this gate.
func (o *nativeActionOwner) Project(ctx context.Context, source *alert.Alert) (EpisodeProjection, error) {
	return o.projectSource(ctx, source, true)
}

func (o *nativeActionOwner) projectSource(ctx context.Context, source *alert.Alert, enroll bool) (EpisodeProjection, error) {
	ctx = o.withEpoch(ctx)
	if source == nil || !o.ready() {
		return EpisodeProjection{}, unavailable
	}
	key, fp := source.ManagedMember.Episode, source.Fingerprint().String()
	s := o.slot(sourceKey(key, fp), false)
	if (s == nil || s.latest() == nil) && o.readSource != nil {
		o.readSource(key, fp, func(current *alert.Alert) {
			if current != source {
				return
			}
			s = o.slot(sourceKey(key, fp), enroll)
			if s != nil && s.latest() == nil {
				o.observe(key, current, false)
			}
		})
	}
	if s == nil {
		return EpisodeProjection{}, unverified
	}
	s.turn.Lock()
	defer s.turn.Unlock()
	if err := o.flush(ctx, s); err != nil {
		return EpisodeProjection{}, err
	}
	p := s.projection
	if err := s.current(p, source, false); err != nil {
		return EpisodeProjection{}, err
	}
	if err := o.verifySource(ctx, source, p.State); err != nil {
		return EpisodeProjection{}, err
	}
	if err := o.publish(ctx, s, p); err != nil {
		return EpisodeProjection{}, err
	}
	if !o.live(ctx) || !o.ready() {
		return EpisodeProjection{}, unavailable
	}
	return p, s.current(p, source, false)
}
func (o *nativeActionOwner) verifySource(ctx context.Context, source *alert.Alert, state string) error {
	if source == nil {
		return unverified
	}
	if !source.ManagedReceiver {
		return nil
	}
	if o.verifyManaged == nil {
		return unverified
	}
	return o.verifyManaged(ctx, source, state)
}

func (o *nativeActionOwner) intent(ctx context.Context, id string) (*actionIntent, error) {
	var i *actionIntent
	err := o.read(ctx, "lookup", map[string]any{"operation_id": id, "projection": "intent"}, &i)
	if i != nil && (i.Result.OperationID != id || !managedHash.MatchString(i.Digest)) {
		return nil, conflict
	}
	return i, err
}
func (o *nativeActionOwner) resolveIntent(ctx context.Context, id string) (*actionIntent, error) {
	lookup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return o.intent(lookup, id)
}
func (o *nativeActionOwner) publish(ctx context.Context, s *episodeSlot, p EpisodeProjection) error {
	source := s.latest()
	err := s.current(p, source, false)
	if err == nil && p.State == "firing" {
		err = o.verifySource(ctx, source, p.State)
	}
	if err == nil {
		err = s.current(p, source, false)
	}
	if err == nil {
		if reader, ok := o.dispatch.(interface {
			PublishSource(context.Context, EpisodeProjection, *alert.Alert) error
		}); ok {
			err = reader.PublishSource(ctx, p, source)
		} else {
			err = o.dispatch.Publish(ctx, p)
		}
	}
	s.needsPublish = err != nil
	return err
}
func (o *nativeActionOwner) Lookup(ctx context.Context, id string) (ActionResultV1, error) {
	var r *ActionResultV1
	if !managedUUID.MatchString(id) {
		return ActionResultV1{}, mismatch
	}
	if err := o.read(ctx, "lookup", map[string]any{"operation_id": id, "projection": "result"}, &r); err != nil {
		return ActionResultV1{}, err
	}
	if r == nil {
		return ActionResultV1{}, actionError{404, "NATIVE_OPERATION_MISSING"}
	}
	return *r, nil
}
func (o *nativeActionOwner) episode(ref EpisodeRef) (*episodeSlot, error) {
	if !validRef(ref) || ref.AuthorityID != o.authority {
		return nil, mismatch
	}
	o.mu.Lock()
	s := o.byID[ref.EpisodeID]
	o.mu.Unlock()
	if s == nil {
		return nil, unverified
	}
	return s, nil
}
func (o *nativeActionOwner) Execute(ctx context.Context, req ActionRequestV1) (ActionResultV1, error) {
	ctx = o.withEpoch(ctx)
	var r ActionResultV1
	if !o.ready() {
		return r, unavailable
	}
	if !validAction(req) {
		return r, conflict
	}
	select {
	case o.slots <- struct{}{}:
		defer func() { <-o.slots }()
	default:
		return r, unavailable
	}
	digest, err := actionDigest(req)
	if err != nil {
		return r, err
	}
	s, sourceErr := o.episode(req.EpisodeRef)
	if sourceErr == nil {
		s.turn.Lock()
		defer s.turn.Unlock()
	}
	i, err := o.intent(ctx, req.OperationID)
	if err != nil {
		return r, err
	}
	if i != nil && i.Digest != digest {
		return r, conflict
	}
	assertion, authorized := ctx.Value(policyAssertionKey{}).(policyAssertion)
	directive := assertion.Recovery
	if req.Actor.Kind == "policy" {
		if !authorized {
			return r, actionError{403, "POLICY_ASSERTION_REQUIRED"}
		}
		if directive == nil && i != nil {
			return i.Result, nil
		}
		if directive != nil && (i == nil || !directive.valid() || directive.CurrentRef.AuthorityID != req.EpisodeRef.AuthorityID || directive.CurrentRef.EpisodeID != req.EpisodeRef.EpisodeID || directive.CurrentRef.Generation != req.EpisodeRef.Generation) {
			return r, reconcile
		}
		if directive != nil && !time.Now().Before(assertion.ExpiresAt) {
			return r, actionError{403, "POLICY_ASSERTION_EXPIRED"}
		}
	}
	if directive != nil && directive.Mode == "transfer" {
		child, found, e := o.linkedPolicyTransfer(ctx, i, *directive)
		if e != nil || found {
			return child, e
		}
	}
	// Terminal and unknown receipts remain lookupable independently of current provider identity.
	if (directive == nil || directive.Mode != "transfer") && i != nil && (i.Result.State == "confirmed" || i.Result.State == "rejected" || i.Result.State == "superseded_no_effect" || (i.Result.State == "unknown" || i.Result.State == "partial") && !slices.ContainsFunc(i.Result.Targets, func(t TargetResult) bool { return t.State == "pending" && t.SuccessorID == nil })) {
		return i.Result, nil
	}
	if sourceErr != nil {
		return r, sourceErr
	}
	ctx = context.WithValue(ctx, sameFloorRetry{}, req.OperationID)
	if err = o.flush(ctx, s); err != nil {
		return r, err
	}
	p := s.projection
	source := s.latest()
	if directive != nil {
		if directive.CurrentRef != p.EpisodeRef || directive.SeverityRevision != p.SeverityRevision {
			return r, mismatch
		}
		if directive.Mode == "transfer" {
			return o.transferPolicy(ctx, s, i, req, *directive, assertion.ExpiresAt)
		}
		if req.EpisodeRef != directive.CurrentRef {
			return r, mismatch
		}
		prior := i.Result.PermitExpiresAt
		if prior != nil {
			// A successful replay returns the same permit. A later renewal needs its exact expiry.
			if o.localDeadline(*prior).After(time.Now()) {
				return i.Result, s.current(p, source, true)
			}
			if directive.PreviousPermit == nil {
				return r, reconcile
			}
			expected, e := time.Parse(time.RFC3339Nano, *directive.PreviousPermit)
			if e != nil || !prior.Equal(expected) {
				return r, reconcile
			}
		} else if directive.PreviousPermit != nil {
			return r, reconcile
		}
	}
	if p.EpisodeRef != req.EpisodeRef {
		return r, mismatch
	}
	if err = s.current(p, source, true); err != nil {
		return r, err
	}
	if err = o.verifySource(ctx, source, p.State); err != nil {
		return r, err
	}
	if i == nil {
		if err = o.write(ctx, "reserve", map[string]any{"request": req, "digest": digest, "expected_revision": p.SeverityRevision}, &r); err != nil {
			prior := err
			i, err = o.resolveIntent(ctx, req.OperationID)
			if err != nil || i == nil {
				return r, prior
			}
			if i.Digest != digest {
				return r, conflict
			}
		} else if r.Reason == nil || *r.Reason != "AWAITING_NATIVE_COMMIT" {
			i, err = o.intent(ctx, req.OperationID)
			if err != nil || i == nil {
				return r, unavailable
			}
			if i.Digest != digest {
				return r, conflict
			}
		}
	}
	proposed := p
	proposed.PreviousEffective = p.EffectiveSeverity()
	var floor *string
	if req.TargetSeverity != nil && firingRanks[*req.TargetSeverity] > firingRanks[p.Floor] {
		floor = req.TargetSeverity
		proposed.Floor = *floor
		proposed.SeverityRevision++
	}
	var targets []DispatchTarget
	reason := ""
	if dispatchKind(req.Kind) {
		targets, reason, err = o.dispatch.Plan(ctx, source, proposed, req)
		if err != nil {
			return r, err
		}
		if i != nil && len(i.Result.Targets) > 0 && reason == "" {
			// A successor and a renewed attempt retain their frozen set, including removed siblings.
			frozen := make([]DispatchTarget, 0, len(i.Result.Targets))
			for _, t := range i.Result.Targets {
				if t.State == "pending" && !slices.ContainsFunc(targets, func(now DispatchTarget) bool { return reflect.DeepEqual(now, t.Target) }) {
					return r, reconcile
				}
				frozen = append(frozen, t.Target)
			}
			targets = frozen
		}
	}
	if targets == nil {
		targets = []DispatchTarget{}
	}
	if reason != "" && (i == nil || i.Intent == nil) {
		// A2 can transfer a suppressed pre-entry reservation only while its intent remains uncommitted.
		if i != nil {
			r = i.Result
		}
		if err = s.current(p, source, true); err != nil {
			return ActionResultV1{}, err
		}
		r.State = "held"
		r.Reason = &reason
		return r, nil
	}
	update := actionCommit{EpisodeRef: p.EpisodeRef, SeverityRevision: proposed.SeverityRevision, Floor: floor, State: "accepted", Targets: targets}
	if reason != "" {
		update = actionCommit{EpisodeRef: p.EpisodeRef, SeverityRevision: p.SeverityRevision, State: "held", Reason: &reason, Targets: []DispatchTarget{}}
	}
	renew := false
	if i != nil && i.Intent != nil && i.Intent.State == "accepted" {
		if i.Result.SeverityRevision != p.SeverityRevision {
			return r, mismatch
		}
		if reason != "" || !equalTargets(targets, i.Intent.Targets) {
			return r, reconcile
		}
		if i.Result.PermitExpiresAt != nil && o.localDeadline(*i.Result.PermitExpiresAt).After(time.Now()) {
			if !o.ready() {
				return r, unavailable
			}
			if err = o.publish(ctx, s, p); err != nil {
				return r, err
			}
			if !o.live(ctx) {
				return r, unavailable
			}
			return i.Result, s.current(p, source, true)
		}
		renew = true
		update = *i.Intent
	}
	if err = s.current(p, source, true); err != nil {
		return r, err
	}
	if directive != nil && !time.Now().Before(assertion.ExpiresAt) {
		return r, actionError{403, "POLICY_ASSERTION_EXPIRED"}
	}
	retryingFloor := s.floorWrite != nil
	if f := s.floorWrite; f != nil && (f.operationID != req.OperationID || !reflect.DeepEqual(f.update, update) || f.digest != digest) {
		return r, reconcile
	}
	s.uncertain = true
	if update.Floor != nil && !renew {
		epoch, _ := ctx.Value(actionEpochKey{}).(uint64)
		s.floorWrite = &pendingFloor{req.OperationID, digest, update, epoch}
		s.local.Lock()
		s.publication++
		s.local.Unlock()
	}
	if err = o.write(ctx, "commit", map[string]any{"operation_id": req.OperationID, "expected_revision": p.SeverityRevision, "update": update, "renew_permit": renew}, &r); err != nil {
		prior := err
		var refusal actionError
		if errors.As(err, &refusal) && refusal.code == 409 {
			// A definitive conflict on an initial write rolls back. An older ambiguous retry can remain outstanding.
			if !retryingFloor {
				s.floorWrite = nil
			}
		}
		i, err = o.resolveIntent(ctx, req.OperationID)
		if err != nil || i == nil || i.Digest != digest || !reflect.DeepEqual(i.Intent, &update) || renew && (i.Result.PermitExpiresAt == nil || !o.localDeadline(*i.Result.PermitExpiresAt).After(time.Now())) {
			return r, prior
		}
		r = i.Result
	}
	if err = s.current(p, source, true); err != nil {
		return ActionResultV1{}, err
	}
	if !o.ready() {
		return ActionResultV1{}, unavailable
	}
	if r.OperationID != req.OperationID || r.EpisodeRef != p.EpisodeRef {
		return ActionResultV1{}, reconcile
	}
	if r.FloorApplied != nil {
		p.Floor = *r.FloorApplied
	}
	p.SeverityRevision = r.SeverityRevision
	s.local.Lock()
	s.publication++
	s.local.Unlock()
	s.projection = p
	s.floorWrite = nil
	s.uncertain = false
	if err = o.publish(ctx, s, p); err != nil {
		return ActionResultV1{}, err
	}
	if r.State == "accepted" && (r.PermitExpiresAt == nil || !o.localDeadline(*r.PermitExpiresAt).After(time.Now())) {
		return ActionResultV1{}, actionError{409, "NATIVE_PERMIT_EXPIRED"}
	}
	if r.State == "accepted" && len(r.Targets) > 0 {
		if err = o.dispatch.Wake(ctx, req.OperationID); err != nil {
			return ActionResultV1{}, err
		}
	}
	if !o.live(ctx) {
		return ActionResultV1{}, unavailable
	}
	return r, s.current(p, source, true)
}
func equalTargets(a, b []DispatchTarget) bool {
	if len(a) != len(b) {
		return false
	}
	encode := func(v []DispatchTarget) []string {
		k := make([]string, len(v))
		for j, t := range v {
			raw, _ := json.Marshal(t)
			k[j] = string(raw)
		}
		slices.Sort(k)
		return k
	}
	return slices.Equal(encode(a), encode(b))
}
func (o *nativeActionOwner) Eligibility(ctx context.Context, refs []EpisodeRef) ([]Eligibility, error) {
	ctx = o.withEpoch(ctx)
	if !o.ready() || len(refs) > 100 {
		return nil, unavailable
	}
	out := make([]Eligibility, 0, len(refs))
	for _, ref := range refs {
		item := Eligibility{EpisodeRef: ref, Actions: map[string]ActionDecision{}}
		s, err := o.episode(ref)
		func() {
			var p EpisodeProjection
			var source *alert.Alert
			if err == nil {
				s.turn.Lock()
				defer s.turn.Unlock()
				if s.uncertain {
					err = reconcile
				}
				p = s.projection
				source = s.latest()
				if err == nil {
					if p.EpisodeRef != ref {
						err = mismatch
					} else {
						err = s.current(p, source, true)
						if err == nil {
							err = o.verifySource(ctx, source, p.State)
						}
					}
				}
			}
			if err == nil {
				revision := p.SeverityRevision
				item.SeverityRevision = &revision
			}
			for kind := range actionGrants {
				reason := ""
				if err != nil {
					reason = err.Error()
				} else if dispatchKind(kind) {
					_, r, e := o.dispatch.Plan(ctx, source, p, ActionRequestV1{Version: 1, EpisodeRef: ref, Kind: kind, TargetScope: []ScopeEntry{}})
					reason = r
					if e != nil {
						reason = unavailable.reason
					}
				}
				d := ActionDecision{Allowed: reason == ""}
				if reason != "" {
					d.Reason = &reason
				}
				item.Actions[kind] = d
			}
		}()
		out = append(out, item)
	}
	return out, nil
}

// InstallActionOwner installs the private command guard outside the existing mutation guards.
func (api *API) InstallActionOwner(c ActionOwnerConfig) error {
	if !c.Enabled {
		api.Handler = actionRoutes(api.Handler, nil, nil, func() bool { return false })
		return nil
	}
	client, err := newManagedClient(c.Scheme, c.CAFile, c.StoreKeyFile)
	if err != nil {
		return err
	}
	keys := map[string][]byte{}
	used := map[string]bool{client.token: true}
	forbidden := append([][]byte{}, api.conversionCallbackKey, api.silenceMutationKey)
	if api.managedOwner != nil {
		forbidden = append(forbidden, []byte(api.managedOwner.client.token))
	}
	for _, k := range api.actionForbidden {
		forbidden = append(forbidden, k)
	}
	for _, k := range forbidden {
		if string(k) == client.token {
			return errors.New("reused native action store credential")
		}
		used[string(k)] = true
	}
	for sender, file := range map[string]string{"operator": c.OperatorKeyFile, "policy": c.PolicyKeyFile} {
		raw, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		k := bytes.TrimSpace(raw)
		if len(k) < 32 || len(k) > 256 || used[string(k)] {
			return errors.New("independent native action caller credential required")
		}
		used[string(k)] = true
		keys[sender] = k
	}
	if c.AuthorityID == "" {
		c.AuthorityID = defaultActionAuthority
	}
	if !managedUUID.MatchString(c.AuthorityID) {
		return errors.New("invalid native action namespace")
	}
	o := newNativeActionOwner(c.AuthorityID, actionClient{client}, c.Dispatch)
	api.actionOwner = o
	o.callbackReady = func() bool { return api.callbacksReadyFor(client, true) }
	ready := o.ready
	api.Handler = actionRoutes(api.Handler, keys, o, ready)
	if c.Dispatch == nil {
		return nil
	}
	store, ok := api.alerts.(interface {
		SetActionObserver(func(string, *alert.Alert, bool))
		ReadActionSource(string, string, func(*alert.Alert))
		ManagedShutdown() <-chan struct{}
	})
	if !ok {
		return errors.New("native action provider unavailable")
	}
	o.readSource = store.ReadActionSource
	if api.managedOwner != nil {
		o.verifyManaged = api.managedOwner.verifyActionMember
		o.lockManaged = func(key string) (func(), error) { _, release, err := api.managedOwner.enter(key); return release, err }
	}
	store.SetActionObserver(o.observe)
	if err = c.Dispatch.Bind(o); err != nil {
		return fmt.Errorf("native action dispatch: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-store.ManagedShutdown(); cancel() }()
	go o.maintain(ctx)
	return nil
}

// actionView returns effective routing labels without performing a journal read on a list endpoint.
func (api *API) actionView(source *alert.Alert) *alert.Alert {
	if o := api.actionOwner; o != nil && o.dispatch != nil && o.dispatch.Version() == 1 {
		if reader, ok := o.dispatch.(interface {
			ReadView(*alert.Alert) *alert.Alert
		}); ok {
			return reader.ReadView(source)
		}
	}
	return source
}
