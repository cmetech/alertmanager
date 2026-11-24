// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/common/model"
)

// ledgerMetrics observes the delivery ledger. Methods accept a nil receiver.
type ledgerMetrics struct {
	decisions     *prometheus.CounterVec
	invalidations *prometheus.CounterVec
}

// registerLedgerMetrics exports the ledger of the current configuration graph.
func registerLedgerMetrics(reg prometheus.Registerer, a *nativeActions) {
	f := promauto.With(reg)
	a.ledgerMetrics = &ledgerMetrics{
		decisions: f.NewCounterVec(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_ledger_decisions_total",
			Help: "Native reader member decisions: skip (covered), defer (backoff) or contact, by reason (new, changed, resolved, due, retry, fallback).",
		}, []string{"decision", "reason"}),
		invalidations: f.NewCounterVec(prometheus.CounterOpts{
			Name: "alertmanager_oscar_native_ledger_invalidations_total",
			Help: "Delivery ledger entries discarded, by cause (lease, config, revision, confirmed_contact).",
		}, []string{"cause"}),
	}
	f.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "alertmanager_oscar_native_ledger_entries",
		Help: "Entries in the delivery ledger of the current configuration graph.",
	}, func() float64 {
		if g := a.snapshot(); g != nil {
			return float64(g.ledger.count())
		}
		return 0
	})
}

func (m *ledgerMetrics) decided(decision, reason string) {
	if m != nil {
		m.decisions.WithLabelValues(decision, reason).Inc()
	}
}

func (m *ledgerMetrics) invalidated(cause string, n int) {
	if m != nil && n > 0 {
		m.invalidations.WithLabelValues(cause).Add(float64(n))
	}
}

func (a *nativeActions) newLedger() *deliveryLedger {
	l := newDeliveryLedger()
	if a != nil {
		l.metrics = a.ledgerMetrics
	}
	return l
}

func (l *deliveryLedger) count() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.size
}

// LedgerView is the read-only lookup view of one ledger entry.
type LedgerView struct {
	Receiver         string     `json:"receiver"`
	Integration      string     `json:"integration"`
	Index            int        `json:"index"`
	GroupKey         string     `json:"group_key"`
	LeaseEpoch       uint64     `json:"lease_epoch"`
	LedgerVersion    uint64     `json:"invalidation_version"`
	EpisodeID        string     `json:"episode_id,omitempty"`
	Generation       uint64     `json:"generation"`
	VariantRevision  uint64     `json:"variant_revision"`
	SeverityRevision uint64     `json:"severity_revision"`
	LifecycleSeq     uint64     `json:"lifecycle_seq"`
	LabelsHash       string     `json:"labels_hash"`
	NextEligible     *time.Time `json:"next_eligible"`
	RetryAttempts    int        `json:"retry_attempts"`
	NextAttempt      *time.Time `json:"next_attempt"`
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// lookup returns every entry for one provider fingerprint without mutating.
// ponytail: linear scan; this is an on-demand diagnostic read.
func (l *deliveryLedger) lookup(fp model.Fingerprint) []LedgerView {
	out := []LedgerView{}
	if l == nil {
		return out
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for t, groups := range l.entries {
		if t.source != fp {
			continue
		}
		for g, e := range groups {
			out = append(out, LedgerView{
				Receiver: t.receiver, Integration: t.integration, Index: t.index, GroupKey: g,
				LeaseEpoch: l.epoch, LedgerVersion: l.version,
				EpisodeID: e.covered.ref.EpisodeID, Generation: e.covered.ref.Generation, VariantRevision: e.covered.ref.VariantRevision,
				SeverityRevision: e.covered.severity, LifecycleSeq: e.covered.lifecycle, LabelsHash: e.covered.labels.String(),
				NextEligible: optionalTime(e.nextEligible), RetryAttempts: e.attempts, NextAttempt: optionalTime(e.nextAttempt),
			})
		}
	}
	return out
}

// LedgerLookup serves the read-only ledger endpoint for the current graph.
func (a *nativeActions) LedgerLookup(fp model.Fingerprint) any {
	g := a.snapshot()
	if g == nil {
		return []LedgerView{}
	}
	return g.ledger.lookup(fp)
}
