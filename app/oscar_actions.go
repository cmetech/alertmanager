// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/inhibit"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/silence"
)

// Remain dormant until the transport and recovery readers qualify together.
const nativeDispatchVersion = 0

var actionHeld = errors.New("ACTION_RECONCILIATION_REQUIRED")

type actionIntegration struct {
	name, digest string
	index        int
	canonical    bool
	maxAlerts    uint64
}
type actionGraph struct {
	supported  bool
	routes     *dispatch.Route
	targets    map[string][]actionIntegration
	inhibitor  *inhibit.Inhibitor
	silencer   *silence.Silencer
	timeMuter  notify.TimeMuter
	dispatcher *dispatch.Dispatcher
	pipeline   notify.Stage
	ctx        context.Context
	cancel     context.CancelFunc
}
type publishedMember struct {
	p      v2.EpisodeProjection
	member *alert.Alert
}
type nativeActions struct {
	scheme, caFile string
	version        int
	mu             sync.RWMutex
	graph          *actionGraph
	journal        v2.ActionJournal
	sources        map[model.Fingerprint]publishedMember
	episodes       map[string]publishedMember
	pending        map[string]bool
	read           func(string, string, func(*alert.Alert))
	key            []byte
	logger         *slog.Logger
}

func newNativeActions(read func(string, string, func(*alert.Alert)), key []byte, logger *slog.Logger) *nativeActions {
	return &nativeActions{version: nativeDispatchVersion, read: read, key: key, logger: logger, sources: make(map[model.Fingerprint]publishedMember), episodes: make(map[string]publishedMember), pending: make(map[string]bool)}
}
func (a *nativeActions) Bind(j v2.ActionJournal) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.journal = j
	return nil
}
func (a *nativeActions) canInstall() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.version == 1 && a.journal != nil
}
func (a *nativeActions) Version() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.journal != nil && a.graph != nil && a.graph.pipeline != nil && a.graph.supported {
		return a.version
	}
	return 0
}
func (a *nativeActions) snapshot() *actionGraph {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.graph
}
func (a *nativeActions) pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.graph != nil {
		a.graph.cancel()
		a.graph = nil
	}
}
func (a *nativeActions) readView(source *alert.Alert, use func(*alert.Alert)) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	p, ok := a.sources[source.Fingerprint()]
	if !ok {
		use(source)
	} else if p.member.ProviderSource() == source {
		use(p.member)
	}
}
func (a *nativeActions) ReadView(source *alert.Alert) *alert.Alert {
	var result *alert.Alert
	a.readView(source, func(v *alert.Alert) { result = v })
	return result
}
func effectiveMember(source *alert.Alert, p v2.EpisodeProjection) (*alert.Alert, error) {
	if p.State == "resolved" && p.EffectiveSeverity() == "cleared" {
		return source, nil
	}
	view, err := alert.BuildDispatchView(source, p.EpisodeRef, p.EffectiveSeverity(), p.SeverityRevision)
	if err != nil {
		return nil, err
	}
	return view.NotificationMember(), nil
}
func (a *nativeActions) Publish(ctx context.Context, p v2.EpisodeProjection) error {
	if p.State != "resolved" {
		return actionHeld
	}
	return a.PublishSource(ctx, p, nil)
}
func (a *nativeActions) PublishSource(ctx context.Context, p v2.EpisodeProjection, source *alert.Alert) error {
	owner := ""
	if p.ManagedOwner != nil {
		owner = p.ManagedOwner.EpisodeKey
	}
	if source != nil {
		verified := false
		a.read(owner, p.NativeVariant.Fingerprint, func(current *alert.Alert) { verified = current == source })
		if !verified {
			return actionHeld
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	g := a.graph
	if g == nil {
		return actionHeld
	}
	prev, ok := a.episodes[p.EpisodeRef.EpisodeID]
	if ok && (prev.p.EpisodeRef.Generation > p.EpisodeRef.Generation || prev.p.EpisodeRef.Generation == p.EpisodeRef.Generation && (prev.p.LifecycleSeq > p.LifecycleSeq || prev.p.LifecycleSeq == p.LifecycleSeq && prev.p.SeverityRevision > p.SeverityRevision)) {
		return actionHeld
	}
	if p.State == "resolved" && source == nil {
		if ok {
			delete(a.episodes, p.EpisodeRef.EpisodeID)
			delete(a.sources, prev.member.ProviderSource().Fingerprint())
			g.inhibitor.UpdateProjection(prev.member.ProviderSource().Fingerprint(), nil)
			g.dispatcher.ReplaceProjection(ctx, prev.member, nil)
		}
		return nil
	}
	start, err := time.Parse(time.RFC3339Nano, p.NativeVariant.StartsAt)
	if source == nil || err != nil || source.Fingerprint().String() != p.NativeVariant.Fingerprint || !source.StartsAt.Equal(start) {
		return actionHeld
	}
	if ok && prev.member.ProviderSource() == source && prev.p.EpisodeRef == p.EpisodeRef && prev.p.SeverityRevision == p.SeverityRevision && prev.p.LifecycleSeq == p.LifecycleSeq {
		return nil
	}
	member, err := effectiveMember(source, p)
	if err != nil {
		return err
	}
	old := source
	if ok {
		old = prev.member
		delete(a.sources, old.ProviderSource().Fingerprint())
	}
	pub := publishedMember{p, member}
	a.episodes[p.EpisodeRef.EpisodeID] = pub
	a.sources[source.Fingerprint()] = pub
	if old.ProviderSource().Fingerprint() != source.Fingerprint() {
		g.inhibitor.UpdateProjection(old.ProviderSource().Fingerprint(), nil)
	}
	g.inhibitor.UpdateProjection(source.Fingerprint(), member)
	g.dispatcher.ReplaceProjection(ctx, old, member)
	return nil
}

func actionScope(receiver string, canonical bool, requested []alert.TargetScopeEntry) ([]alert.TargetScopeEntry, bool) {
	scope := []alert.TargetScopeEntry{}
	if len(requested) == 0 {
		return scope, true
	}
	for _, s := range requested {
		if s.ReceiverID != receiver {
			continue
		}
		if s.NotifierID == nil {
			return []alert.TargetScopeEntry{s}, true
		}
		if canonical {
			scope = append(scope, s)
		}
	}
	return scope, len(scope) > 0
}

type plannedContact struct {
	v2.DispatchTarget
	integration actionIntegration
	route       *dispatch.Route
}

func (g *actionGraph) contacts(ctx context.Context, source *alert.Alert, p v2.EpisodeProjection, scope []alert.TargetScopeEntry) ([]plannedContact, error) {
	member, err := effectiveMember(source, p)
	if err != nil {
		return nil, err
	}
	labels := []*alert.Alert{source, member}
	if p.PreviousEffective != "" && p.PreviousEffective != p.EffectiveSeverity() {
		v, err := alert.BuildDispatchView(source, p.EpisodeRef, p.PreviousEffective, p.SeverityRevision)
		if err != nil {
			return nil, err
		}
		labels = append(labels, v.NotificationMember())
	}
	for _, m := range labels {
		available := false
		for _, route := range g.routes.Match(m.Labels) {
			opts := route.RouteOpts
			active, muted, err := notify.MutedByTimeIntervals(g.timeMuter, opts.ActiveTimeIntervals, opts.MuteTimeIntervals, time.Now())
			if err != nil {
				return nil, err
			}
			if len(active)+len(muted) == 0 {
				available = true
				break
			}
		}
		if !available {
			return nil, nil
		}
		if g.inhibitor.MutesSource(ctx, m.LabelSet(), source.Fingerprint()) || g.silencer.Mutes(ctx, m.LabelSet()) {
			return nil, nil
		}
	}
	var contacts []plannedContact
	seen := map[string]bool{}
	for _, route := range g.routes.Match(member.Labels) {
		opts := route.RouteOpts
		active, muted, err := notify.MutedByTimeIntervals(g.timeMuter, opts.ActiveTimeIntervals, opts.MuteTimeIntervals, time.Now())
		if err != nil {
			return nil, err
		}
		if len(active)+len(muted) > 0 {
			continue
		}
		for _, i := range g.targets[opts.Receiver] {
			frozen, ok := actionScope(opts.Receiver, i.canonical, scope)
			if !ok || source.ManagedReceiver && !i.canonical || seen[i.digest] {
				continue
			}
			seen[i.digest] = true
			interval := opts.RepeatInterval.Microseconds()
			if opts.RepeatInterval%time.Microsecond != 0 {
				interval++
			}
			contacts = append(contacts, plannedContact{v2.DispatchTarget{ReceiverID: opts.Receiver, IntegrationDigest: i.digest, Scope: frozen, RepeatIntervalUS: interval}, i, route})
		}
	}
	return contacts, nil
}
func (a *nativeActions) Plan(ctx context.Context, s *alert.Alert, p v2.EpisodeProjection, req v2.ActionRequestV1) ([]v2.DispatchTarget, string, error) {
	g := a.snapshot()
	if g == nil {
		return nil, "", actionHeld
	}
	contacts, err := g.contacts(ctx, s, p, req.TargetScope)
	if err != nil {
		return nil, "", err
	}
	if len(contacts) == 0 {
		return nil, "NATIVE_SUPPRESSED", nil
	}
	out := make([]v2.DispatchTarget, len(contacts))
	for i, t := range contacts {
		out[i] = t.DispatchTarget
	}
	return out, "", nil
}
func (a *nativeActions) Wake(_ context.Context, id string) error {
	a.mu.Lock()
	g := a.graph
	if g == nil || len(a.pending) >= 32 {
		a.mu.Unlock()
		return actionHeld
	}
	if a.pending[id] {
		a.mu.Unlock()
		return nil
	}
	a.pending[id] = true
	a.mu.Unlock()
	go func() {
		defer func() { a.mu.Lock(); delete(a.pending, id); a.mu.Unlock() }()
		ctx, cancel := context.WithTimeout(g.ctx, 30*time.Second)
		defer cancel()
		if err := a.dispatchPending(ctx, g, id); err != nil {
			a.logger.Debug("native action pending", "operation", id, "err", err)
		}
	}()
	return nil
}
func (a *nativeActions) dispatchPending(ctx context.Context, g *actionGraph, id string) error {
	r, err := a.journal.Lookup(ctx, id)
	if err != nil {
		return err
	}
	a.mu.RLock()
	pub, ok := a.episodes[r.EpisodeRef.EpisodeID]
	a.mu.RUnlock()
	if !ok || pub.p.EpisodeRef != r.EpisodeRef || pub.p.SeverityRevision != r.SeverityRevision {
		return actionHeld
	}
	source := pub.member.ProviderSource()
	var result error
	for _, t := range r.Targets {
		if t.State != "pending" || t.SuccessorID != nil {
			continue
		}
		contacts, err := g.contacts(ctx, source, pub.p, t.Target.Scope)
		if err != nil {
			return err
		}
		for _, c := range contacts {
			if !reflect.DeepEqual(c.DispatchTarget, t.Target) {
				continue
			}
			member := pub.member.NotificationCopy(time.Now())
			cctx := g.dispatcher.SelectedContext(ctx, c.route, member)
			s := notify.SelectedAction{Source: source, Receiver: c.ReceiverID, Integration: c.integration.name, Index: c.integration.index,
				Invoke: func(ctx context.Context, i *notify.Integration, m *alert.Alert) notify.NotifyVerdict {
					return a.invoke(ctx, g, i, []*alert.Alert{m}, []ordinaryContact{{operation: id, target: t, contact: c, p: pub.p}}, 0)
				}}
			_, _, err = g.pipeline.Exec(notify.WithSelectedAction(cctx, s), a.logger, member)
			result = errors.Join(result, err)
			break
		}
	}
	return result
}

type ordinaryContact struct {
	operation string
	target    v2.TargetResult
	contact   plannedContact
	p         v2.EpisodeProjection
	pass      *v2.OrdinaryPass
}

func (a *nativeActions) prepare(ctx context.Context, g *actionGraph, receiver, name string, index int, members []*alert.Alert, due func([]*alert.Alert) bool) (notify.OrdinaryBatch, error) {
	var result notify.OrdinaryBatch
	if g == nil || g != a.snapshot() {
		return result, actionHeld
	}
	match := slices.IndexFunc(g.targets[receiver], func(i actionIntegration) bool { return i.index == index && i.name == name })
	if match < 0 {
		return result, actionHeld
	}
	i := g.targets[receiver][match]
	var ordinary []*alert.Alert
	var held error
	contacts := make(map[*alert.Alert]ordinaryContact, len(members))
	for _, m := range members {
		source := m.ProviderSource()
		p, pass, err := a.journal.InspectOrdinary(ctx, source)
		if err != nil {
			held = err
			continue
		}
		c := ordinaryContact{pass: pass, contact: plannedContact{DispatchTarget: v2.DispatchTarget{ReceiverID: receiver}, integration: i}}
		if p != nil {
			c.p = *p
			view, err := effectiveMember(source, *p)
			if err != nil || !view.Labels.Equal(m.Labels) || p.State == "resolved" && !m.TerminalWireValid() {
				held = actionHeld
				continue
			}
		}
		if p == nil || p.State == "resolved" {
			ordinary = append(ordinary, m)
		}
		contacts[m] = c
	}
	groupDue, subsetDue := due(members), due(ordinary)
	for _, m := range members {
		c, ok := contacts[m]
		if !ok {
			continue
		}
		if c.p.State != "firing" {
			source := m.ProviderSource()
			terminal := c.p.State == "resolved" || source.Resolved() || source.ManagedReceiver && source.ManagedOperationKind == "clear"
			if terminal && !groupDue || !terminal && !subsetDue {
				delete(contacts, m)
				continue
			}
		}
		result.Members = append(result.Members, m)
	}
	if len(result.Members) == 0 {
		return result, held
	}
	full := len(result.Members) == len(members)
	if i.maxAlerts != 0 {
		// An unverifiable member could occupy the native post-send_resolved prefix.
		if held != nil {
			return result, held
		}
		// Keep nondue positions until RetryStage filters resolved members and Invoke fixes the prefix.
		result.Members = members
	}
	var logMembers []*alert.Alert
	if full {
		// RetryStage can finish an all-resolved, send_resolved=false batch without invoking a provider.
		logMembers = members
	}
	result.LogMembers = func() ([]*alert.Alert, error) { return logMembers, held }
	result.Invoke = func(ctx context.Context, integration *notify.Integration, sent []*alert.Alert) notify.NotifyVerdict {
		var truncated uint64
		if limit := i.maxAlerts; limit != 0 && uint64(len(sent)) > limit {
			truncated = uint64(len(sent)) - limit
			sent = sent[:limit]
		}
		var pending, accepted []*alert.Alert
		var entries []ordinaryContact
		var ordinaryAcceptance bool
		for _, m := range sent {
			c, eligible := contacts[m]
			if !eligible {
				continue
			}
			c, err := a.ordinaryContact(ctx, g, m, c)
			if err != nil {
				if err.Error() != "NATIVE_SUPPRESSED" {
					held = errors.Join(held, err)
				}
				continue
			}
			accepted = append(accepted, m)
			if c.target.State == "confirmed" {
				continue
			}
			ordinaryAcceptance = ordinaryAcceptance || c.pass != nil || c.p.State == "resolved"
			pending = append(pending, m)
			entries = append(entries, c)
		}
		if len(pending) > 0 {
			v := a.invoke(ctx, g, integration, pending, entries, truncated)
			if v.Err() != nil {
				return v
			}
		}
		switch {
		case full && len(sent) > 0 && len(accepted) == len(sent):
			logMembers = members // Native truncation still acknowledges the original ordinary group.
		case ordinaryAcceptance:
			logMembers = accepted // Record successful ordinary siblings even when another contact was covered or held.
		default:
			logMembers = nil
		}
		if len(logMembers) == 0 && held != nil {
			return notify.Unrecoverable(held, notify.DefaultReason)
		}
		return notify.Success()
	}
	return result, nil
}
func currentGroup(ctx context.Context, m *alert.Alert, r *dispatch.Route) bool {
	key, _ := notify.GroupKey(ctx)
	return dispatch.GroupKeyForAlert(m, r) == key
}
func (a *nativeActions) reserve(ctx context.Context, p v2.EpisodeProjection, t plannedContact) (ordinaryContact, error) {
	id := uuid.NewString()
	r, err := a.journal.ReserveOrdinary(ctx, id, p.EpisodeRef, t.DispatchTarget, false)
	if err != nil {
		return ordinaryContact{}, err
	}
	if len(r.Targets) != 1 || r.Targets[0].State != "pending" || r.Targets[0].SuccessorID != nil {
		return ordinaryContact{}, actionHeld
	}
	return ordinaryContact{operation: id, target: r.Targets[0], contact: t, p: p}, nil
}

// ordinaryContact reserves only members selected by native send_resolved filtering and truncation.
func (a *nativeActions) ordinaryContact(ctx context.Context, g *actionGraph, m *alert.Alert, c ordinaryContact) (ordinaryContact, error) {
	s := m.ProviderSource()
	if c.pass != nil {
		if !c.contact.integration.canonical {
			return c, nil
		}
		p, err := a.journal.Project(ctx, s)
		if err != nil {
			return c, err
		}
		view, err := effectiveMember(s, p)
		if err != nil || !m.Labels.Equal(view.Labels) {
			return c, actionHeld
		}
		c.pass, c.p = nil, p
	}
	if c.p.State == "resolved" && !m.TerminalWireValid() {
		return c, actionHeld
	}
	possible, err := g.contacts(ctx, m.ProviderSource(), c.p, nil)
	if err != nil {
		return c, err
	}
	idx := slices.IndexFunc(possible, func(t plannedContact) bool {
		return t.ReceiverID == c.contact.ReceiverID && t.IntegrationDigest == c.contact.integration.digest && currentGroup(ctx, m, t.route)
	})
	if idx < 0 {
		return c, actionHeld
	}
	c.contact = possible[idx]
	if c.p.State == "firing" {
		return a.reserve(ctx, c.p, c.contact)
	}
	if c.p.State != "resolved" {
		return c, actionHeld
	}
	r, err := a.journal.ReserveTerminal(ctx, m, c.p, c.contact.DispatchTarget)
	if err != nil {
		return c, err
	}
	if len(r.Targets) != 1 || !reflect.DeepEqual(r.Targets[0].Target, c.contact.DispatchTarget) {
		return c, actionHeld
	}
	c.operation, c.target = r.OperationID, r.Targets[0]
	switch c.target.State {
	case "pending", "confirmed":
		return c, nil
	default:
		return c, actionHeld
	}
}

func (a *nativeActions) invoke(ctx context.Context, g *actionGraph, i *notify.Integration, members []*alert.Alert, contacts []ordinaryContact, truncated uint64) notify.NotifyVerdict {
	var claimed []v2.Entry
	var passes []*v2.OrdinaryPass
	entered := false
	finish := func(v notify.NotifyVerdict) notify.NotifyVerdict {
		outcome, evidence := "no_effect", "FENCED_BEFORE_PROVIDER_ENTRY"
		if entered {
			outcome, evidence = "confirmed", "NATIVE_TRANSPORT_ACCEPTED"
			if v.Err() != nil {
				outcome, evidence = "unknown", "NATIVE_TRANSPORT_ACCEPTANCE_UNKNOWN"
			}
		}
		for _, p := range passes {
			p.Finish(!entered || v.Err() == nil)
		}
		late, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		for _, e := range claimed {
			if _, err := a.journal.Settle(late, e, outcome, evidence); err != nil {
				v = notify.Unrecoverable(err, notify.DefaultReason)
			}
		}
		return v
	}
	fail := func(err error) notify.NotifyVerdict { return finish(notify.Unrecoverable(err, notify.DefaultReason)) }
	bound := &notify.ProviderEntry{Truncated: truncated}
	for x, c := range contacts {
		s := members[x].ProviderSource()
		var entry v2.Entry
		if c.operation != "" {
			e, err := a.journal.Claim(ctx, c.operation, c.target.TargetKey)
			if err != nil {
				return fail(err)
			}
			claimed = append(claimed, e)
			if e == nil || !e.ForMember(members[x]) {
				return fail(actionHeld)
			}
			entry = e
		}
		if c.contact.integration.canonical {
			operation, err := uuid.Parse(c.operation)
			if entry == nil || err != nil {
				return fail(actionHeld)
			}
			id := uuid.NewSHA1(operation, []byte(c.target.TargetKey)).String()
			stamp, err := a.journal.Delivery(ctx, s, c.contact.ReceiverID, id, entry)
			if err != nil {
				return fail(err)
			}
			bound.Members = append(bound.Members, alert.NativeDeliveryMember{Index: x, Delivery: stamp})
			bound.Key = a.key
		}
	}
	bound.Begin = func() bool {
		if entered || g != a.snapshot() || ctx.Err() != nil {
			return false
		}
		for x, c := range contacts {
			s := members[x].ProviderSource()
			if c.pass != nil {
				if !c.pass.Enter() {
					return false
				}
				passes = append(passes, c.pass)
			} else if c.operation == "" {
				return false
			}
			if c.operation != "" {
				now, err := g.contacts(ctx, s, c.p, c.target.Target.Scope)
				if err != nil || !slices.ContainsFunc(now, func(t plannedContact) bool {
					return t.route == c.contact.route && reflect.DeepEqual(c.target.Target, t.DispatchTarget)
				}) {
					return false
				}
			}
		}
		for _, e := range claimed {
			if !e.Valid() {
				return false
			}
		}
		for _, e := range claimed {
			if !e.LocalValid() {
				return false
			}
		}
		if g != a.snapshot() || ctx.Err() != nil {
			return false
		}
		entered = true
		return true
	}
	if i.Name() != "webhook" {
		return fail(actionHeld)
	}
	v := i.Notify(notify.WithProviderEntry(ctx, bound), members...)
	if !entered && v.Err() == nil {
		return fail(actionHeld)
	}
	return finish(v)
}

func actionDestinations(conf *config.Config, receivers map[string][]notify.Integration) (map[string][]actionIntegration, bool, error) {
	digests, err := conf.ActionIntegrationDigests()
	if err != nil {
		return nil, false, err
	}
	out := map[string][]actionIntegration{}
	allSupported := true
	for _, r := range conf.Receivers {
		for _, i := range receivers[r.Name] {
			ds := digests[r.Name][i.Name()]
			if i.Index() >= len(ds) {
				return nil, false, fmt.Errorf("missing configuration for %s/%s", r.Name, i.String())
			}
			target := actionIntegration{name: i.Name(), index: i.Index(), digest: ds[i.Index()]}
			if i.Name() == "webhook" {
				webhook := r.WebhookConfigs[i.Index()]
				target.maxAlerts = webhook.MaxAlerts
				url := string(webhook.URL)
				if webhook.URLFile != "" || strings.Contains(url, "{{") {
					allSupported = false
				}
				for _, scheme := range []string{"http", "https"} {
					base := scheme + "://alertmanager-middleware:9400" + alert.NativeCallbackPath
					if url == base || url == base+"?notifier_type=oscaradmin" {
						target.canonical = true
					}
				}
			} else {
				allSupported = false
			}
			out[r.Name] = append(out[r.Name], target)
		}
	}
	return out, allSupported, nil
}
