// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package inhibit

import (
	"strings"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/common/model"
)

// The exact index is capped separately for each rule. Overflow holds only that
// rule's target matchers and clears as soon as its last excess member leaves.
const maxUnresolvedPairs = 4096

type possibleInhibitor struct {
	source   *alert.Alert
	oneSided bool
}
type unresolvedRule struct {
	keys            map[model.Fingerprint]map[model.Fingerprint]possibleInhibitor
	count, overflow int
}

// possibleKeys folds alternative severities for this resident into its distinct
// equal keys. Keep the raw (including missing) label as an alternative.
func (r *InhibitRule) possibleKeys(a *alert.Alert) map[model.Fingerprint]bool {
	keys := map[model.Fingerprint]bool{}
	view := a.Labels.Clone()
	observe := func() {
		if r.SourceMatchers.Matches(view) {
			key := r.cache.fingerprintEquals(view)
			keys[key] = keys[key] || !r.TargetMatchers.Matches(view)
		}
	}
	observe()
	severities := []string{"info", "minor", "warning", "major", "critical"}
	raw := strings.ToLower(string(view["severity"]))
	if strings.TrimSpace(raw) == "" {
		raw = "major"
	}
	feasible := false
	for _, sev := range severities {
		feasible = feasible || sev == raw
		if feasible {
			view["severity"] = model.LabelValue(sev)
			observe()
		}
	}
	return keys
}

// UpdateUnresolved installs uncertainty about one current provider member. It
// never writes to the confirmed inhibitor cache or the alert marker.
func (ih *Inhibitor) UpdateUnresolved(fp model.Fingerprint, source *alert.Alert) {
	ih.uncertainMu.Lock()
	defer ih.uncertainMu.Unlock()
	old := ih.uncertain[fp]
	if old == source {
		return
	}
	for _, r := range ih.rules {
		idx := &r.unknown
		if old != nil {
			for k := range r.possibleKeys(old) {
				group := idx.keys[k]
				if _, ok := group[fp]; ok {
					delete(group, fp)
					if len(group) == 0 {
						delete(idx.keys, k)
					}
					idx.count--
				} else {
					idx.overflow--
				}
			}
		}
		if source != nil {
			for k, one := range r.possibleKeys(source) {
				if idx.count >= maxUnresolvedPairs {
					idx.overflow++
					continue
				}
				if idx.keys == nil {
					idx.keys = make(map[model.Fingerprint]map[model.Fingerprint]possibleInhibitor)
				}
				if idx.keys[k] == nil {
					idx.keys[k] = make(map[model.Fingerprint]possibleInhibitor)
				}
				idx.keys[k][fp] = possibleInhibitor{source, one}
				idx.count++
			}
		}
	}
	if source == nil {
		delete(ih.uncertain, fp)
	} else {
		if ih.uncertain == nil {
			ih.uncertain = make(map[model.Fingerprint]*alert.Alert)
		}
		ih.uncertain[fp] = source
	}
}

// MayDependOnUnresolved identifies a possible dependency for an actual target
// view, including the native self and two-sided exclusions.
func (ih *Inhibitor) MayDependOnUnresolved(target model.LabelSet, source model.Fingerprint) bool {
	ih.uncertainMu.RLock()
	defer ih.uncertainMu.RUnlock()
	now := time.Now()
	for _, r := range ih.rules {
		if !r.TargetMatchers.Matches(target) {
			continue
		}
		if r.unknown.overflow > 0 {
			return true
		}
		for fp, possible := range r.unknown.keys[r.cache.fingerprintEquals(target)] {
			if fp != source && !possible.source.ResolvedAt(now) && (possible.oneSided || !r.SourceMatchers.Matches(target)) {
				return true
			}
		}
	}
	return false
}

// HasInhibitor checks the native rule cache without recording an additional
// muted event for each local provider recheck.
func (ih *Inhibitor) HasInhibitor(target model.LabelSet, source model.Fingerprint) bool {
	now := time.Now()
	for _, r := range ih.rules {
		if r.TargetMatchers.Matches(target) {
			if _, ok := r.findEqual(target, r.SourceMatchers.Matches(target), now, &source); ok {
				return true
			}
		}
	}
	return false
}
