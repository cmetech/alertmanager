// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v2

import (
	"fmt"
	"slices"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/prometheus/alertmanager/alert"
	models "github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
)

const oscarTimingScanBudget = 200000

const (
	timingLookupReady       = "ready"
	timingLookupUnavailable = "unavailable"
	timingStateEstimated    = "estimated"
	timingStateNoBaseline   = "no_repeat_baseline"
	timingStateSuppressed   = "suppressed"
	timingStateUnavailable  = "unavailable"
)

// TimingIntegration identifies one integration in the loaded notification
// pipeline. Its name and index use the same key as native deduplication.
type TimingIntegration struct {
	Name  string
	Index uint32
}

type TimingLookupFunc func(string, *nflogpb.Receiver, []uint64, int) nflog.TimingLookup

// TimingSource contains immutable metadata published only after a dispatcher
// generation has loaded. A nil Lookup leaves paths unavailable.
type TimingSource struct {
	Integrations map[string][]TimingIntegration
	Muter        notify.TimeMuter
	Lookup       TimingLookupFunc
}

func (api *API) PauseTiming() {
	api.mtx.Lock()
	api.timing = nil
	api.mtx.Unlock()
}

// PublishTiming makes timing metadata available for the current API config.
// A stale reload cannot publish metadata for a newer config generation.
func (api *API) PublishTiming(cfg *config.Config, integrations map[string][]TimingIntegration, muter notify.TimeMuter, lookup TimingLookupFunc) {
	api.mtx.Lock()
	defer api.mtx.Unlock()
	if api.alertmanagerConfig != cfg {
		return
	}
	copyMap := make(map[string][]TimingIntegration, len(integrations))
	for name, items := range integrations {
		copyMap[name] = slices.Clone(items)
	}
	api.timing = &TimingSource{Integrations: copyMap, Muter: muter, Lookup: lookup}
}

type timingTarget struct {
	hash     uint64
	step     *models.OscarRepeatSchedule
	interval time.Duration
}

type timingGroup struct {
	key      string
	receiver *nflogpb.Receiver
	hashes   map[uint64]struct{}
	targets  []timingTarget
}

type timingPageStats struct {
	lookups     int
	inspected   int
	cappedPaths int
}

func timingForPage(rows []pageCandidate, route *dispatch.Route, source *TimingSource, asOf time.Time) map[string]models.OscarAlertTiming {
	out, _ := timingForPageWithStats(rows, route, source, asOf)
	return out
}

func timingForPageWithStats(rows []pageCandidate, route *dispatch.Route, source *TimingSource, asOf time.Time) (map[string]models.OscarAlertTiming, timingPageStats) {
	out := make(map[string]models.OscarAlertTiming, len(rows))
	stats := timingPageStats{}
	groups := make(map[string]*timingGroup)
	keys := make([]string, 0)
	for _, c := range rows {
		endSource := string(c.a.EndTimeSource)
		if endSource == "" {
			endSource = string(alert.EndTimeSourceUnknown)
		}
		lookupState := timingLookupUnavailable
		if source != nil && route != nil {
			lookupState = timingLookupReady
		}
		stamp := strfmt.DateTime(asOf)
		meta := models.OscarAlertTiming{
			EndTimeSource:     &endSource,
			RepeatLookupState: &lookupState,
			RepeatSchedules:   []*models.OscarRepeatSchedule{},
			TimingAsOf:        &stamp,
		}
		if c.a.EndTimeSource == alert.EndTimeSourceAlertmanagerTimeout {
			duration := c.a.ResolveTimeout.String()
			meta.ResolveTimeoutDuration = &duration
		}
		if source != nil && route != nil {
			seenMuteNames := make(map[string]struct{})
			muteStateKnown := true
			for _, matched := range route.Match(c.a.Labels) {
				if len(matched.RouteOpts.ActiveTimeIntervals) > 0 || len(matched.RouteOpts.MuteTimeIntervals) > 0 {
					if source.Muter == nil {
						muteStateKnown = false
					} else {
						active, muted, err := notify.MutedByTimeIntervals(source.Muter, matched.RouteOpts.ActiveTimeIntervals, matched.RouteOpts.MuteTimeIntervals, asOf)
						if err != nil {
							muteStateKnown = false
						} else {
							for _, name := range slices.Concat(active, muted) {
								if _, seen := seenMuteNames[name]; !seen {
									seenMuteNames[name] = struct{}{}
									meta.MutedBy = append(meta.MutedBy, name)
								}
							}
						}
					}
				}
				receiverName := matched.RouteOpts.Receiver
				for _, integration := range source.Integrations[receiverName] {
					routeID := matched.ID()
					integrationID := fmt.Sprintf("%s/%d", integration.Name, integration.Index)
					interval := matched.RouteOpts.RepeatInterval
					intervalString := interval.String()
					state := timingStateNoBaseline
					step := &models.OscarRepeatSchedule{
						RouteID:                &routeID,
						Receiver:               &receiverName,
						Integration:            &integrationID,
						RepeatIntervalDuration: &intervalString,
						State:                  &state,
					}
					meta.RepeatSchedules = append(meta.RepeatSchedules, step)
					if c.status.State == alert.AlertStateSuppressed || len(c.status.SilencedBy) > 0 || len(c.status.InhibitedBy) > 0 {
						*step.State = timingStateSuppressed
						continue
					}
					if len(matched.RouteOpts.ActiveTimeIntervals) > 0 || len(matched.RouteOpts.MuteTimeIntervals) > 0 {
						if source.Muter == nil {
							*step.State = timingStateUnavailable
							continue
						}
						active, muted, err := notify.MutedByTimeIntervals(source.Muter, matched.RouteOpts.ActiveTimeIntervals, matched.RouteOpts.MuteTimeIntervals, asOf)
						if err != nil {
							*step.State = timingStateUnavailable
							continue
						}
						if len(active) > 0 || len(muted) > 0 {
							*step.State = timingStateSuppressed
							continue
						}
					}
					if source.Lookup == nil {
						*step.State = timingStateUnavailable
						continue
					}
					groupKey := dispatch.GroupKeyForAlert(c.a, matched)
					recv := &nflogpb.Receiver{GroupName: receiverName, Integration: integration.Name, Idx: integration.Index}
					key := fmt.Sprintf("%s:%s/%s/%d", groupKey, receiverName, integration.Name, integration.Index)
					group := groups[key]
					if group == nil {
						group = &timingGroup{key: groupKey, receiver: recv, hashes: make(map[uint64]struct{})}
						groups[key] = group
						keys = append(keys, key)
					}
					hash := notify.HashAlert(c.a)
					group.hashes[hash] = struct{}{}
					group.targets = append(group.targets, timingTarget{hash: hash, step: step, interval: interval})
				}
			}
			if !muteStateKnown {
				meta.MutedBy = nil
			} else if meta.MutedBy == nil {
				meta.MutedBy = []string{}
			}
		}
		out[c.fingerprint] = meta
	}

	remaining := oscarTimingScanBudget
	for _, key := range keys {
		group := groups[key]
		hashes := make([]uint64, 0, len(group.hashes))
		for hash := range group.hashes {
			hashes = append(hashes, hash)
		}
		slices.Sort(hashes)
		result := source.Lookup(group.key, group.receiver, hashes, remaining)
		stats.lookups++
		stats.inspected += result.Inspected
		remaining -= result.Inspected
		for _, target := range group.targets {
			if result.Capped {
				*target.step.State = timingStateUnavailable
				stats.cappedPaths++
				continue
			}
			if !result.Found || !result.Firing[target.hash] {
				continue
			}
			threshold := result.Timestamp.Add(target.interval)
			if !result.ExpiresAt.After(asOf) || !result.ExpiresAt.After(threshold) {
				*target.step.State = timingStateUnavailable
				continue
			}
			*target.step.State = timingStateEstimated
			date := strfmt.DateTime(threshold)
			target.step.NextRepeatEligibleAt = &date
		}
	}
	return out, stats
}
