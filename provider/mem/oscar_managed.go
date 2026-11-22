package mem

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/common/model"
	"go.opentelemetry.io/otel/propagation"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/provider"
)

const maxManagedBatchItems = 4096
const maxManagedBatchBytes = 16 << 20

// One committed batch owns the stream until delivery. Ordinary writes backpressure
// at this turn outside the provider lock. Subscribers may independently take snapshots.
type orderedHandoff struct{ turn chan struct{} }

func (h *orderedHandoff) acquire(ctx context.Context, shutdown <-chan struct{}) error {
	select {
	case h.turn <- struct{}{}:
		return nil
	case <-shutdown:
		return context.Canceled
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EnableManaged is a bootstrap operation before the provider is published.
func (a *Alerts) EnableManaged() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.handoff.Load() != nil {
		return
	}
	a.stamps = make(map[string]provider.ManagedStamp)
	a.manualFinal = make(map[string]bool)
	a.owners = make(map[model.Fingerprint]string)
	a.variants = make(map[string]map[model.Fingerprint]bool)
	a.handoff.Store(&orderedHandoff{turn: make(chan struct{}, 1)})
}

func (a *Alerts) subscribers() []listeningAlerts {
	targets := make([]listeningAlerts, 0, len(a.listeners))
	for _, listener := range a.listeners {
		targets = append(targets, listener)
	}
	return targets
}

func (a *Alerts) drain(stream *orderedHandoff, targets []listeningAlerts, messages []*provider.Alert) {
	defer func() { <-stream.turn }()
	for _, message := range messages {
		for _, listener := range targets {
			select {
			case listener.alerts <- message:
				if a.subscriberChannelWrites != nil {
					a.subscriberChannelWrites.WithLabelValues(listener.name).Inc()
				}
			case <-listener.done:
			case <-a.shutdown:
				return
			}
		}
	}
}

func managedSize(a *alert.Alert) int {
	n := 256 + len(a.GeneratorURL)
	for k, v := range a.Labels {
		n += 32 + len(k) + len(v)
	}
	for k, v := range a.Annotations {
		n += 32 + len(k) + len(v)
	}
	return n
}

// ApplyManaged replaces every currently owned problem in one provider commit.
// A nil incoming alert retires the problems fenced by an operator close.
func (a *Alerts) ApplyManaged(ctx context.Context, owner string, incoming *alert.Alert, stamp provider.ManagedStamp, validate func() error) error {
	return a.applyOrdered(ctx, owner, incoming, stamp, nil, false, validate)
}

// ApplyManual installs an admitted manual publication under its exact preceding stamp.
// Restore may seed only an empty, privately unowned provider after process restart.
func (a *Alerts) ApplyManual(ctx context.Context, owner string, incoming *alert.Alert, stamp, prior provider.ManagedStamp, restore bool, validate func() error) error {
	if incoming == nil || incoming.ManualEpisode == "" || owner != incoming.ActionOwner() || stamp.Generation < 1 || incoming.ManualStamp != stamp.Digest {
		return errors.New("invalid manual publication")
	}
	return a.applyOrdered(ctx, owner, incoming, stamp, &prior, restore, validate)
}

func (a *Alerts) applyOrdered(ctx context.Context, owner string, incoming *alert.Alert, stamp provider.ManagedStamp, manualPrior *provider.ManagedStamp, restore bool, validate func() error) error {
	stream := a.handoff.Load()
	if stream == nil || owner == "" || validate == nil {
		return errors.New("managed provider unavailable")
	}
	if err := stream.acquire(ctx, a.shutdown); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			<-stream.turn
		}
	}()
	a.mtx.Lock()
	defer a.mtx.Unlock()
	now := time.Now()
	if incoming != nil && incoming.StartsAt.After(now) {
		return errors.New("managed start is ahead of native clock")
	}
	if manualPrior != nil {
		applied, exists := a.stamps[owner]
		if exists && applied == stamp {
			current, err := a.alerts.Get(incoming.Fingerprint())
			if err != nil && incoming.ManualTerminal && a.owners[incoming.Fingerprint()] == owner && a.variants[owner][incoming.Fingerprint()] {
				// The exact stored terminal stamp survives normal resolved GC.
				return validate()
			}
			if err != nil || a.owners[incoming.Fingerprint()] != owner || current.ManualStamp != stamp.Digest ||
				current.ManualTerminal != incoming.ManualTerminal || !current.StartsAt.Equal(incoming.StartsAt) || !current.EndsAt.Equal(incoming.EndsAt) || !current.Labels.Equal(incoming.Labels) || !current.Annotations.Equal(incoming.Annotations) {
				return errors.New("manual publication resident mismatch")
			}
			return validate()
		}
		if restore && exists || !restore && applied != *manualPrior || !restore && exists && stamp.Generation != applied.Generation+1 {
			return errors.New("manual publication predecessor mismatch")
		}
		if exists {
			found := false
			for fp, active := range a.variants[owner] {
				if !active {
					continue
				}
				old, err := a.alerts.Get(fp)
				if err != nil || a.owners[fp] != owner || old.ManualStamp != applied.Digest || old.ManualTerminal {
					return errors.New("manual predecessor unavailable")
				}
				found = true
			}
			if !found {
				return errors.New("manual predecessor missing")
			}
		}
	}
	var changes []*alert.Alert
	size := 0
	existing := make(map[model.Fingerprint]bool)
	for fp := range a.variants[owner] {
		if incoming != nil && incoming.Fingerprint() == fp {
			continue
		}
		old, err := a.alerts.Get(fp)
		if err != nil || manualPrior == nil && (old.Labels["alert_type"] != "problem" || old.ResolvedAt(now)) || manualPrior != nil && !a.variants[owner][fp] {
			continue
		}
		if old.StartsAt.After(now) {
			return errors.New("managed retirement precedes start")
		}
		retired := *old
		retired.Labels, retired.Annotations = old.Labels.Clone(), old.Annotations.Clone()
		retired.EndsAt, retired.UpdatedAt, retired.Timeout = now, now, false
		retired.ManualTerminal = manualPrior != nil
		retired.EndTimeSource = alert.EndTimeSourceSender
		changes = append(changes, &retired)
		size += managedSize(&retired)
		existing[fp] = true
		if len(changes) > maxManagedBatchItems || size > maxManagedBatchBytes {
			return errors.New("managed retirement capacity exceeded")
		}
	}
	if incoming != nil {
		copy := *incoming
		copy.Labels, copy.Annotations = incoming.Labels.Clone(), incoming.Annotations.Clone()
		copy.ManagedReceiver = manualPrior == nil
		incoming = &copy
		fp := incoming.Fingerprint()
		if _, tracked := a.variants[owner][fp]; !tracked && len(a.variants[owner]) >= maxManagedBatchItems {
			return errors.New("managed variant capacity exceeded")
		}
		old, err := a.alerts.Get(fp)
		if (a.owners[fp] != "" && a.owners[fp] != owner) || (err == nil && (a.owners[fp] != owner || !old.Labels.Equal(incoming.Labels))) {
			return errors.New("managed fingerprint collision")
		}
		existing[fp] = err == nil
		changes = append(changes, incoming)
		size += managedSize(incoming)
	}
	if len(changes) > maxManagedBatchItems || size > maxManagedBatchBytes {
		return errors.New("managed batch capacity exceeded")
	}
	for _, change := range changes {
		if err := a.callback.PreStore(change, existing[change.Fingerprint()]); err != nil {
			return err
		}
	}
	if err := a.alerts.SetBatch(changes, func() error {
		prior := a.stamps[owner]
		if prior.Generation > stamp.Generation || (prior.Generation == stamp.Generation && prior.Generation != 0 && prior != stamp) {
			return errors.New("managed provider generation conflict")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return validate()
	}); err != nil {
		return err
	}
	a.stamps[owner] = stamp
	refs := a.variants[owner]
	if refs == nil {
		refs = make(map[model.Fingerprint]bool)
		a.variants[owner] = refs
	}
	for fp := range refs {
		refs[fp] = false
		if _, err := a.alerts.Get(fp); err != nil {
			delete(refs, fp)
			delete(a.owners, fp)
		}
	}
	if incoming != nil {
		fp := incoming.Fingerprint()
		refs[fp] = true
		a.owners[fp] = owner
	}
	if len(refs) == 0 {
		delete(a.variants, owner)
	}
	if a.actionObserver != nil {
		a.actionObserver(owner, incoming, incoming == nil)
	}
	metadata := map[string]string{}
	a.propagator.Inject(ctx, propagation.MapCarrier(metadata))
	messages := make([]*provider.Alert, 0, len(changes))
	for _, change := range changes {
		a.callback.PostStore(change, existing[change.Fingerprint()])
		if a.observer != nil {
			a.observer.Upserted(change)
		}
		messages = append(messages, &provider.Alert{Data: change, Header: metadata})
	}
	targets := a.subscribers()
	committed = true
	go a.drain(stream, targets, messages)
	return nil
}

func (a *Alerts) ManagedShutdown() <-chan struct{} { return a.shutdown }

// ManagedApplied returns a copy of the receipt written with the store batch.
func (a *Alerts) ManagedApplied(owner string) (provider.ManagedStamp, bool) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	stamp, ok := a.stamps[owner]
	return stamp, ok
}

// FinalizeManual releases a terminal tombstone after its SQL commit and native GC, in either order.
func (a *Alerts) FinalizeManual(owner string, stamp provider.ManagedStamp) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.stamps[owner] != stamp {
		return
	}
	a.manualFinal[owner] = true
	for fp, current := range a.variants[owner] {
		if current {
			if _, err := a.alerts.Get(fp); err == nil {
				return
			}
			delete(a.owners, fp)
			delete(a.variants[owner], fp)
		}
	}
	if len(a.variants[owner]) == 0 {
		delete(a.variants, owner)
	}
	delete(a.manualFinal, owner)
	delete(a.stamps, owner)
}

// ReleaseManaged drops the stale generation only after SQL archived the close.
// A still-visible clear receipt remains protected until its normal native GC.
func (a *Alerts) ReleaseManaged(key string, generation int64) {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if a.stamps[key].Generation > generation {
		return
	}
	delete(a.stamps, key)
	refs := a.variants[key]
	for fp := range refs {
		refs[fp] = false
		if _, err := a.alerts.Get(fp); err != nil {
			delete(refs, fp)
			delete(a.owners, fp)
		}
	}
	if len(refs) == 0 {
		delete(a.variants, key)
	}
}
