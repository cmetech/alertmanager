// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/config/receiver"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
)

// ledgerJournal is a fake OSCAR that models ordinary coverage the way
// native_action_state.py does: an unchanged firing member is covered while
// now < next_eligible at the same variant and severity revision, and a
// confirmed settle stamps next_eligible = settle time + repeat interval.
// Every journal RPC is counted per episode. InspectOrdinary is not: in
// production the reader uses the local published projection instead.
type ledgerJournal struct {
	terminalFixtureJournal
	mu          sync.Mutex
	now         func() time.Time
	advance     func(time.Duration) // OSCAR handles a settle this much later
	settleDelay time.Duration
	coverage    map[string]ledgerCoverage // episode ID
	issued      map[v2.Entry]v2.OrdinaryCandidate
	fail        map[string]bool // episode IDs whose calls fail
	untilReply  bool            // return next_eligible on covered rows (OSC-144)
	calls       map[string]int
	total       atomic.Int64
	settleErr   error
}

type ledgerCoverage struct {
	next              time.Time
	variant, revision uint64
}

func (j *ledgerJournal) call(p v2.EpisodeProjection) {
	j.calls[p.EpisodeRef.EpisodeID]++
	j.total.Add(1)
}

func (j *ledgerJournal) coveredLocked(p v2.EpisodeProjection) bool {
	c, ok := j.coverage[p.EpisodeRef.EpisodeID]
	return p.State == "firing" && ok && j.now().Before(c.next) && c.variant == p.EpisodeRef.VariantRevision && c.revision == p.SeverityRevision
}

func (*ledgerJournal) CohortReady() bool     { return true }
func (*ledgerJournal) CohortSupported() bool { return true }

func (j *ledgerJournal) InspectCohort(_ context.Context, members []v2.OrdinaryCandidate) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	states := make([]string, len(members))
	for i, m := range members {
		j.call(m.Projection)
		states[i] = "due"
		if j.fail[m.Projection.EpisodeRef.EpisodeID] {
			states[i] = "held"
		} else if j.coveredLocked(m.Projection) {
			states[i] = "covered"
		}
	}
	return states
}

func (j *ledgerJournal) AdmitCohort(_ context.Context, members []v2.OrdinaryCandidate) []v2.OrdinaryAdmission {
	j.mu.Lock()
	defer j.mu.Unlock()
	rows := make([]v2.OrdinaryAdmission, len(members))
	for i, m := range members {
		p := m.Projection
		j.call(p)
		switch {
		case j.fail[p.EpisodeRef.EpisodeID]:
			rows[i].Err = errors.New("NATIVE_UNAVAILABLE")
		case j.coveredLocked(p):
			rows[i].Covered = true
			if j.untilReply {
				rows[i].CoveredUntil = j.coverage[p.EpisodeRef.EpisodeID].next
			}
		default:
			e := &fixturePermit{m.Member.ProviderSource()}
			j.issued[e] = m
			rows[i] = v2.OrdinaryAdmission{Entry: e, TargetKey: p.EpisodeRef.EpisodeID}
		}
	}
	return rows
}

func (j *ledgerJournal) SettleCohort(_ context.Context, rows []v2.OrdinaryReceipt) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.settleDelay > 0 {
		j.advance(j.settleDelay)
	}
	for _, r := range rows {
		m := j.issued[r.Entry]
		p := m.Projection
		j.call(p)
		if r.Outcome == "confirmed" && p.State == "firing" {
			j.coverage[p.EpisodeRef.EpisodeID] = ledgerCoverage{j.now().Add(time.Duration(m.Target.RepeatIntervalUS) * time.Microsecond), p.EpisodeRef.VariantRevision, p.SeverityRevision}
		}
	}
	return j.settleErr
}

func (j *ledgerJournal) Project(ctx context.Context, s *alert.Alert) (v2.EpisodeProjection, error) {
	j.call(j.projections[s])
	return j.terminalFixtureJournal.Project(ctx, s)
}

func (j *ledgerJournal) InspectContact(ctx context.Context, m *alert.Alert, p v2.EpisodeProjection, t v2.DispatchTarget) (string, error) {
	j.call(p)
	return j.terminalFixtureJournal.InspectContact(ctx, m, p, t)
}

func (j *ledgerJournal) ReserveTerminal(ctx context.Context, m *alert.Alert, p v2.EpisodeProjection, t v2.DispatchTarget) (v2.ActionResultV1, error) {
	j.call(p)
	return j.terminalFixtureJournal.ReserveTerminal(ctx, m, p, t)
}

func (j *ledgerJournal) ReserveOrdinary(ctx context.Context, id string, m *alert.Alert, p v2.EpisodeProjection, t v2.DispatchTarget) (v2.ActionResultV1, error) {
	j.call(p)
	return j.terminalFixtureJournal.ReserveOrdinary(ctx, id, m, p, t)
}

func (j *ledgerJournal) Claim(ctx context.Context, id, key string) (v2.Entry, error) {
	j.total.Add(1)
	return j.terminalFixtureJournal.Claim(ctx, id, key)
}

func (j *ledgerJournal) Settle(ctx context.Context, e v2.Entry, outcome, evidence string) (v2.ActionResultV1, error) {
	j.total.Add(1)
	return j.terminalFixtureJournal.Settle(ctx, e, outcome, evidence)
}

type ledgerHarness struct {
	t           *testing.T
	r           *reloader
	a           *nativeActions
	j           *ledgerJournal
	g           *actionGraph
	cfg         *config.Config
	integration *notify.Integration
	posts       atomic.Int64
	clock       time.Time
	sources     []*alert.Alert
}

func newLedgerHarness(t *testing.T, n int, groupBy string) *ledgerHarness {
	t.Helper()
	h := &ledgerHarness{t: t, clock: time.Now()}
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { h.posts.Add(1) }))
	t.Cleanup(sink.Close)
	cfg, err := config.Load(fmt.Sprintf("route:\n  receiver: team\n  group_by: %s\n  group_wait: 1h\n  repeat_interval: 1h\nreceivers:\n- name: team\n  webhook_configs:\n  - url: %s\n    send_resolved: true\n", groupBy, sink.URL))
	require.NoError(t, err)
	h.cfg = cfg
	h.j = &ledgerJournal{coverage: map[string]ledgerCoverage{}, issued: map[v2.Entry]v2.OrdinaryCandidate{}, fail: map[string]bool{}, calls: map[string]int{}}
	h.j.now = func() time.Time { return h.clock }
	h.j.advance = func(d time.Duration) { h.clock = h.clock.Add(d) }
	h.j.projections = map[*alert.Alert]v2.EpisodeProjection{}
	h.j.state = "pending"
	h.r = newTestReloader(t)
	t.Cleanup(func() { _ = h.r.stop() })
	tmpl, err := template.FromGlobs(nil)
	require.NoError(t, err)
	tmpl.ExternalURL = h.r.externalURL
	integrations, err := receiver.BuildReceiverIntegrations(cfg.Receivers[0], tmpl, h.r.logger, commoncfg.WithDialContextFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, sink.Listener.Addr().String())
	}))
	require.NoError(t, err)
	h.integration = &integrations[0]
	h.a = newNativeActions(nil, nil, h.r.logger)
	h.r.actions = h.a
	require.NoError(t, h.a.Bind(h.j))
	require.NoError(t, h.r.reload(cfg))
	h.useGraph()
	require.Nil(t, h.g.targets["team"][0].prepared, "the canonical OSCAR callback shape: an unprepared webhook")
	for k := range n {
		h.add(fmt.Sprintf("A%04d", k))
	}
	return h
}

func (h *ledgerHarness) useGraph() {
	h.g = h.a.snapshot()
	h.g.ledger.now = func() time.Time { return h.clock }
}

func (h *ledgerHarness) add(name string, host ...string) *alert.Alert {
	labels := model.LabelSet{"alertname": model.LabelValue(name), "severity": "major"}
	if len(host) > 0 {
		labels["host"] = model.LabelValue(host[0])
	}
	now := time.Now()
	s := alert.New(model.Alert{Labels: labels, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(24 * time.Hour)}, now, false)
	p := restoredFixture(h.t, s)
	p.Floor = ""
	p.ID = fmt.Sprintf("22222222-2222-4222-8222-%012d", len(h.j.projections)+1)
	p.EpisodeRef.EpisodeID = p.ID
	h.j.projections[s] = p
	h.sources = append(h.sources, s)
	return s
}

// resolve replaces a firing source with its resolved successor (same episode).
func (h *ledgerHarness) resolve(s *alert.Alert) *alert.Alert {
	now := time.Now()
	r := alert.New(model.Alert{Labels: s.Labels, StartsAt: s.StartsAt, EndsAt: now.Add(-time.Second)}, now, false)
	p := h.j.projections[s]
	p.State = "resolved"
	p.LifecycleSeq++
	delete(h.j.projections, s)
	h.j.projections[r] = p
	return r
}

func (h *ledgerHarness) ctxFor(m *alert.Alert) context.Context {
	return h.g.dispatcher.SelectedContext(h.t.Context(), h.g.routes, m)
}

func (h *ledgerHarness) key(s *alert.Alert) ledgerKey {
	m := s.NotificationCopy(time.Now())
	return ledgerKeyFor(h.ctxFor(m), "team", "webhook", 0, m)
}

// flush runs one group_interval tick of the native reader for one group.
func (h *ledgerHarness) flush(group ...*alert.Alert) error {
	members := make([]*alert.Alert, len(group))
	for i, s := range group {
		members[i] = s.NotificationCopy(time.Now())
	}
	ctx := h.ctxFor(members[0])
	batch, err := h.a.prepare(ctx, h.g, "team", "webhook", 0, members, func([]*alert.Alert) bool { return true })
	if err != nil || len(batch.Members) == 0 {
		return err
	}
	return batch.Invoke(ctx, h.integration, batch.Members).Err()
}

// tick flushes every source as its own (ungrouped) group.
func (h *ledgerHarness) tick() {
	for _, s := range h.sources {
		_ = h.flush(s)
	}
}

func (h *ledgerHarness) calls(s *alert.Alert) int {
	return h.j.calls[h.j.projections[s].EpisodeRef.EpisodeID]
}

func TestLedgerAC1UnchangedAlertsAfterConfirm(t *testing.T) {
	h := newLedgerHarness(t, 1000, "['...']")
	h.tick() // first contact: admit + settle(confirmed) per alert
	require.EqualValues(t, 2000, h.j.total.Load())
	require.EqualValues(t, 1000, h.posts.Load())
	before := h.j.total.Load()
	for range 10 {
		h.clock = h.clock.Add(30 * time.Second)
		h.tick()
	}
	require.LessOrEqual(t, h.j.total.Load()-before, int64(1000), "AC-1: at most 1,000 OSCAR calls over 10 unchanged ticks")
	require.Zero(t, h.j.total.Load()-before, "a confirmed, unchanged alert is answered from the ledger")
	require.EqualValues(t, 1000, h.posts.Load(), "nothing is re-sent")
}

func TestLedgerAC1RecoversFromCoveredDeadline(t *testing.T) {
	// OSC-144: once OSCAR returns next_eligible on covered rows, an empty
	// ledger (restart, epoch or reload) is rebuilt by one covered reply.
	h := newLedgerHarness(t, 1, "['...']")
	s := h.sources[0]
	require.NoError(t, h.flush(s))
	h.g.ledger = newDeliveryLedger() // as after a restart
	h.useGraph()
	require.NoError(t, h.flush(s))
	require.NoError(t, h.flush(s))
	require.Equal(t, 4, h.calls(s), "without the deadline every tick asks again")
	h.j.untilReply = true
	require.NoError(t, h.flush(s))
	for range 10 {
		h.clock = h.clock.Add(30 * time.Second)
		require.NoError(t, h.flush(s))
	}
	require.Equal(t, 5, h.calls(s), "one covered reply with next_eligible restores the skip")
}

func TestLedgerAC2ContactsOnChange(t *testing.T) {
	setup := func(t *testing.T) (*ledgerHarness, *alert.Alert) {
		h := newLedgerHarness(t, 1, "['...']")
		s := h.sources[0]
		require.NoError(t, h.flush(s))
		h.clock = h.clock.Add(30 * time.Second)
		require.NoError(t, h.flush(s))
		require.Equal(t, 2, h.calls(s), "confirmed and unchanged: no call")
		return h, s
	}
	t.Run("new", func(t *testing.T) {
		h, _ := setup(t)
		s := h.add("fresh")
		require.NoError(t, h.flush(s))
		require.Equal(t, 2, h.calls(s))
	})
	t.Run("severity revision change", func(t *testing.T) {
		h, s := setup(t)
		p := h.j.projections[s]
		p.SeverityRevision++
		h.j.projections[s] = p
		require.NoError(t, h.flush(s))
		require.Equal(t, 4, h.calls(s), "re-admitted and delivered")
	})
	t.Run("resolve", func(t *testing.T) {
		h, s := setup(t)
		r := h.resolve(s)
		require.NoError(t, h.flush(r))
		require.Greater(t, h.calls(r), 2, "the terminal member reaches OSCAR on the next tick")
		require.EqualValues(t, 2, h.posts.Load())
	})
	t.Run("repeat due", func(t *testing.T) {
		h, s := setup(t)
		h.clock = h.clock.Add(time.Hour)
		require.NoError(t, h.flush(s))
		require.Equal(t, 4, h.calls(s), "repeat re-admitted and confirmed")
	})
	t.Run("retry due", func(t *testing.T) {
		h := newLedgerHarness(t, 1, "['...']")
		s := h.sources[0]
		h.j.fail[h.j.projections[s].EpisodeRef.EpisodeID] = true
		require.Error(t, h.flush(s))
		h.j.fail = map[string]bool{}
		h.clock = h.clock.Add(30 * time.Second)
		require.NoError(t, h.flush(s))
		require.Equal(t, 3, h.calls(s))
	})
	for _, change := range []string{"resolve", "severity"} {
		t.Run(change+" during backoff", func(t *testing.T) {
			h := newLedgerHarness(t, 1, "['...']")
			s := h.sources[0]
			id := h.j.projections[s].EpisodeRef.EpisodeID
			for range 5 { // deep into the backoff (5 m step)
				h.j.fail[id] = true
				_ = h.flush(s)
				h.clock = h.clock.Add(5 * time.Minute)
			}
			h.clock = h.clock.Add(-4 * time.Minute) // well inside the current backoff
			h.j.fail = map[string]bool{}
			calls := h.calls(s)
			if change == "resolve" {
				s = h.resolve(s)
			} else {
				p := h.j.projections[s]
				p.SeverityRevision++
				h.j.projections[s] = p
			}
			require.NoError(t, h.flush(s))
			require.Greater(t, h.calls(s), calls, "a changed member is contacted on the next tick despite backoff")
		})
	}
}

func TestLedgerAC3PerAlertBackoff(t *testing.T) {
	h := newLedgerHarness(t, 0, "[alertname]")
	group := []*alert.Alert{h.add("G", "good"), h.add("G", "bad")} // one group, two members
	bad := group[1]
	h.j.fail[h.j.projections[bad].EpisodeRef.EpisodeID] = true
	require.Error(t, h.flush(group...))
	require.Equal(t, 2, h.calls(group[0]), "sibling admitted and confirmed")
	require.Equal(t, 1, h.calls(bad))
	start := h.clock
	var contactedAt []time.Duration
	last := h.calls(bad)
	for step := 30 * time.Second; step <= 15*time.Minute; step += 30 * time.Second { // group_interval ticks
		h.clock = start.Add(step)
		_ = h.flush(group...)
		if n := h.calls(bad); n != last {
			contactedAt = append(contactedAt, step)
			last = n
		}
	}
	// Retries 30 s, 1 m, 2 m, 4 m, then every 5 m, each measured from the failing flush.
	require.Equal(t, []time.Duration{30 * time.Second, 90 * time.Second, 210 * time.Second, 450 * time.Second, 750 * time.Second}, contactedAt)
	require.Equal(t, 2, h.calls(group[0]), "AC-3: the confirmed sibling is never re-checked or re-sent")
	require.EqualValues(t, 1, h.posts.Load())
}

func TestLedgerAC3DeferredResolvedKeepsGroup(t *testing.T) {
	h := newLedgerHarness(t, 0, "[alertname]")
	s := h.add("G", "a")
	r := h.resolve(s)
	sibling := h.add("G", "b")
	m := r.NotificationCopy(time.Now())
	h.g.ledger.fail(h.key(r), 0, snapOf(h.j.projections[r], m, h.clock), h.clock)
	calls := h.j.total.Load()
	require.ErrorIs(t, h.flush(r), errRetryBackoff, "alone: the flush fails so the dispatcher keeps the resolve")
	require.Equal(t, calls, h.j.total.Load(), "no RPC during backoff")
	err := h.flush(r, sibling)
	require.Equal(t, 2, h.calls(sibling), "the deferred resolve does not hold back a new sibling")
	require.ErrorIs(t, err, errRetryBackoff, "and the group still reports the hold")
}

func TestLedgerAC4ClearsOnEpochAndReload(t *testing.T) {
	h := newLedgerHarness(t, 1, "['...']")
	s := h.sources[0]
	require.NoError(t, h.flush(s))
	require.NoError(t, h.flush(s))
	require.Equal(t, 2, h.calls(s))
	m := s.NotificationCopy(time.Now())
	snap := snapOf(h.j.projections[s], m, h.clock)
	require.True(t, h.g.ledger.covered(h.key(s), 0, snap))
	require.False(t, h.g.ledger.covered(h.key(s), 9, snap), "AC-4: a new lease epoch clears the ledger")
	require.False(t, h.g.ledger.covered(h.key(s), 0, snap), "and the entry is gone")

	require.NoError(t, h.flush(s)) // ask OSCAR: covered, no deadline, no entry (strict)
	require.Equal(t, 3, h.calls(s))
	require.NoError(t, h.flush(s))
	require.Equal(t, 4, h.calls(s))
	require.NoError(t, h.r.reload(h.cfg))
	require.Eventually(t, func() bool { return h.a.snapshot() != h.g }, time.Second, time.Millisecond)
	old := h.g
	h.useGraph()
	require.NotSame(t, old.ledger, h.g.ledger, "AC-4: a configuration reload (new publication generation) starts a new ledger")
}

func TestLedgerAC5SkipStrictness(t *testing.T) {
	l := newDeliveryLedger()
	now := time.Now()
	l.now = func() time.Time { return now }
	s := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "x"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
	p := restoredFixture(t, s)
	k := ledgerKey{group: "g", receiver: "team", integration: "webhook", source: s.Fingerprint()}
	snap := snapOf(p, s, now)
	require.False(t, l.covered(k, 1, snap), "no entry")
	l.settled(k, 1, false)
	require.False(t, l.covered(k, 1, snap), "a covered reply without a deadline creates no skip")
	l.cover(k, 1, snap, now.Add(time.Hour))
	require.True(t, l.covered(k, 1, snap))
	for name, change := range map[string]func(*ledgerSnap){
		"generation":       func(s *ledgerSnap) { s.ref.Generation++ },
		"variant revision": func(s *ledgerSnap) { s.ref.VariantRevision++ },
		"episode":          func(s *ledgerSnap) { s.ref.EpisodeID = "other" },
		"severity":         func(s *ledgerSnap) { s.severity++ },
		"lifecycle":        func(s *ledgerSnap) { s.lifecycle++ },
		"labels":           func(s *ledgerSnap) { s.labels++ },
		"terminal":         func(s *ledgerSnap) { s.terminal = true },
	} {
		q := snap
		change(&q)
		require.False(t, l.covered(k, 1, q), name)
	}
	other := k
	other.group = "another route"
	require.False(t, l.covered(other, 1, snap), "another route's group has its own coverage row")

	// Terminal on the wire or at the source even while OSCAR's view is firing.
	resolvedWire := alert.New(model.Alert{Labels: s.Labels, StartsAt: s.StartsAt, EndsAt: now.Add(-time.Second)}, now, false)
	require.True(t, snapOf(p, resolvedWire, now).terminal)
	clear := alert.New(model.Alert{Labels: s.Labels, StartsAt: s.StartsAt, EndsAt: now.Add(time.Hour)}, now, false)
	clear.ManagedOperationKind = "clear"
	require.True(t, snapOf(p, clear, now).terminal)

	now = now.Add(time.Hour)
	require.False(t, l.covered(k, 1, snap), "deadline reached")

	// The recorded deadline precedes OSCAR's: it is taken before the settle request.
	h := newLedgerHarness(t, 1, "['...']")
	src := h.sources[0]
	h.j.settleDelay = time.Second // OSCAR stamps next_eligible a second later
	require.NoError(t, h.flush(src))
	e := h.g.ledger.entries[h.key(src)]
	require.NotNil(t, e)
	oscar := h.j.coverage[h.j.projections[src].EpisodeRef.EpisodeID].next
	require.True(t, e.nextEligible.Before(oscar), "local %s must precede OSCAR %s", e.nextEligible, oscar)

	// A failed settlement records nothing.
	h2 := newLedgerHarness(t, 1, "['...']")
	h2.j.settleErr = errors.New("lost reply")
	_ = h2.flush(h2.sources[0])
	e = h2.g.ledger.entries[h2.key(h2.sources[0])]
	require.True(t, e == nil || e.nextEligible.IsZero())
}

func TestLedgerBackoffScheduleAndBound(t *testing.T) {
	l := newDeliveryLedger()
	now := time.Now()
	l.now = func() time.Time { return now }
	k := ledgerKey{receiver: "r"}
	snap := ledgerSnap{severity: 1}
	var got []time.Duration
	for range 6 {
		l.fail(k, 0, snap, now)
		got = append(got, l.entries[k].nextAttempt.Sub(now))
	}
	require.Equal(t, []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}, got)
	require.True(t, l.deferred(k, 0, snap))
	require.False(t, l.deferred(k, 0, ledgerSnap{severity: 2}), "a changed member is not deferred")
	require.False(t, l.deferred(k, 0, snap), "and its backoff restarts")
	l.fail(k, 0, snap, now)
	l.settled(k, 0, false)
	require.False(t, l.deferred(k, 0, snap))

	for n := range ledgerMaxEntries + 10 {
		l.fail(ledgerKey{index: n}, 0, snap, now)
	}
	require.LessOrEqual(t, len(l.entries), ledgerMaxEntries)
}
