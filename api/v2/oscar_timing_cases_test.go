// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

package v2

import (
	"testing"
	"time"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/nflog"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
	"github.com/prometheus/alertmanager/notify"
)

func timingTestRows(now time.Time) ([]pageCandidate, *dispatch.Route) {
	rows := make([]pageCandidate, 0, 2)
	for _, instance := range []string{"a", "b"} {
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "LinkDown", "instance": model.LabelValue(instance)}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, false)
		rows = append(rows, pageCandidate{a: a, fingerprint: a.Fingerprint().String(), status: alert.AlertStatus{State: alert.AlertStateActive}})
	}
	cfg, err := config.Load("route:\n  receiver: team\n  group_by: [alertname]\n  repeat_interval: 1h\nreceivers:\n- name: team\n")
	if err != nil {
		panic(err)
	}
	return rows, dispatch.NewRoute(cfg.Route, nil)
}

func TestOscarTimingSharedGroupUsesPerAlertMembershipAndOneLookup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows, route := timingTestRows(now)
	first := notify.HashAlert(rows[0].a)
	second := notify.HashAlert(rows[1].a)
	require.NotEqual(t, first, second)
	called := 0
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(_ string, _ *nflogpb.Receiver, hashes []uint64, budget int) nflog.TimingLookup {
		called++
		require.ElementsMatch(t, []uint64{first, second}, hashes)
		require.Equal(t, oscarTimingScanBudget, budget)
		return nflog.TimingLookup{Found: true, Timestamp: now.Add(-30 * time.Minute), ExpiresAt: now.Add(2 * time.Hour), Firing: map[uint64]bool{first: true}, Inspected: 2}
	}}
	got := timingForPage(rows, route, source, now)
	require.Equal(t, 1, called)
	require.Equal(t, "estimated", *got[rows[0].fingerprint].RepeatSchedules[0].State)
	require.Equal(t, "no_repeat_baseline", *got[rows[1].fingerprint].RepeatSchedules[0].State)
	require.Nil(t, got[rows[1].fingerprint].RepeatSchedules[0].NextRepeatEligibleAt)
}

func TestOscarTimingRequiresLiveLogThroughEligibility(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows, route := timingTestRows(now)
	rows = rows[:1]
	hash := notify.HashAlert(rows[0].a)
	for _, tc := range []struct {
		name   string
		result nflog.TimingLookup
		state  string
	}{
		{"first send failed", nflog.TimingLookup{}, "no_repeat_baseline"},
		{"failed repeat keeps past threshold", nflog.TimingLookup{Found: true, Timestamp: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour), Firing: map[uint64]bool{hash: true}}, "estimated"},
		{"expires before observation", nflog.TimingLookup{Found: true, Timestamp: now.Add(-2 * time.Hour), ExpiresAt: now, Firing: map[uint64]bool{hash: true}}, "unavailable"},
		{"expires before threshold", nflog.TimingLookup{Found: true, Timestamp: now, ExpiresAt: now.Add(30 * time.Minute), Firing: map[uint64]bool{hash: true}}, "unavailable"},
		{"entry over budget", nflog.TimingLookup{Found: true, Capped: true}, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(string, *nflogpb.Receiver, []uint64, int) nflog.TimingLookup { return tc.result }}
			got := timingForPage(rows, route, source, now)[rows[0].fingerprint].RepeatSchedules[0]
			require.Equal(t, tc.state, *got.State)
			require.Equal(t, tc.state == "estimated", got.NextRepeatEligibleAt != nil)
		})
	}
}

func TestOscarTimingUnavailableDuringReloadAndReadyWithoutIntegration(t *testing.T) {
	now := time.Now().UTC()
	rows, route := timingTestRows(now)
	rows = rows[:1]
	missing := timingForPage(rows, route, nil, now)[rows[0].fingerprint]
	require.Equal(t, "unavailable", *missing.RepeatLookupState)
	require.Empty(t, missing.RepeatSchedules)
	ready := timingForPage(rows, route, &TimingSource{Integrations: map[string][]TimingIntegration{}}, now)[rows[0].fingerprint]
	require.Equal(t, "ready", *ready.RepeatLookupState)
	require.Empty(t, ready.RepeatSchedules)
}

func TestOscarTimingContinuingRoutesShareNativeKeyButKeepIntervals(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows, _ := timingTestRows(now)
	rows = rows[:1]
	cfg, err := config.Load("route:\n  receiver: fallback\n  group_by: [alertname]\n  routes:\n  - receiver: team\n    matchers: [instance=\"a\"]\n    continue: true\n    repeat_interval: 1h\n  - receiver: team\n    matchers: [instance=\"a\"]\n    repeat_interval: 2h\nreceivers:\n- name: fallback\n- name: team\n")
	require.NoError(t, err)
	route := dispatch.NewRoute(cfg.Route, nil)
	hash := notify.HashAlert(rows[0].a)
	lookups := 0
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(_ string, _ *nflogpb.Receiver, hashes []uint64, _ int) nflog.TimingLookup {
		lookups++
		require.Equal(t, []uint64{hash}, hashes)
		return nflog.TimingLookup{Found: true, Timestamp: now, ExpiresAt: now.Add(3 * time.Hour), Firing: map[uint64]bool{hash: true}, Inspected: 1}
	}}
	schedules := timingForPage(rows, route, source, now)[rows[0].fingerprint].RepeatSchedules
	require.Equal(t, 1, lookups)
	require.Len(t, schedules, 2)
	require.NotEqual(t, *schedules[0].RouteID, *schedules[1].RouteID)
	require.Equal(t, "1h0m0s", *schedules[0].RepeatIntervalDuration)
	require.Equal(t, "2h0m0s", *schedules[1].RepeatIntervalDuration)
	require.Equal(t, "estimated", *schedules[0].State)
	require.Equal(t, "estimated", *schedules[1].State)
}

func TestOscarTimingSuppressedAlertDoesNotInspectLog(t *testing.T) {
	now := time.Now().UTC()
	rows, route := timingTestRows(now)
	rows = rows[:1]
	rows[0].status = alert.AlertStatus{State: alert.AlertStateSuppressed, SilencedBy: []string{"silence-1"}}
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(string, *nflogpb.Receiver, []uint64, int) nflog.TimingLookup {
		t.Fatal("suppressed path queried notification log")
		return nflog.TimingLookup{}
	}}
	step := timingForPage(rows, route, source, now)[rows[0].fingerprint].RepeatSchedules[0]
	require.Equal(t, "suppressed", *step.State)
	require.Nil(t, step.NextRepeatEligibleAt)
}

func TestOscarTimingTotalLookupBudgetCapsLaterGroup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rows, _ := timingTestRows(now)
	cfg, err := config.Load("route:\n  receiver: team\n  group_by: [instance]\n  repeat_interval: 1h\nreceivers:\n- name: team\n")
	require.NoError(t, err)
	route := dispatch.NewRoute(cfg.Route, nil)
	budgets := make([]int, 0, 2)
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(_ string, _ *nflogpb.Receiver, hashes []uint64, budget int) nflog.TimingLookup {
		budgets = append(budgets, budget)
		if len(budgets) == 1 {
			return nflog.TimingLookup{Found: true, Timestamp: now, ExpiresAt: now.Add(2 * time.Hour), Firing: map[uint64]bool{hashes[0]: true}, Inspected: oscarTimingScanBudget}
		}
		return nflog.TimingLookup{Found: true, Capped: true}
	}}
	got := timingForPage(rows, route, source, now)
	require.Equal(t, []int{oscarTimingScanBudget, 0}, budgets)
	states := []string{*got[rows[0].fingerprint].RepeatSchedules[0].State, *got[rows[1].fingerprint].RepeatSchedules[0].State}
	require.ElementsMatch(t, []string{"estimated", "unavailable"}, states)
}

func TestOscarTimingReportsLookupWorkAndCappedPaths(t *testing.T) {
	now := time.Now().UTC()
	rows, route := timingTestRows(now)
	rows = rows[:1]
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Lookup: func(string, *nflogpb.Receiver, []uint64, int) nflog.TimingLookup {
		return nflog.TimingLookup{Found: true, Capped: true, Inspected: 0}
	}}
	_, stats := timingForPageWithStats(rows, route, source, now)
	require.Equal(t, 1, stats.lookups)
	require.Equal(t, 0, stats.inspected)
	require.Equal(t, 1, stats.cappedPaths)
}

type timingMuter struct{}

func (timingMuter) Mutes(names []string, _ time.Time) (bool, []string, error) {
	if len(names) > 0 {
		return true, names, nil
	}
	return false, nil, nil
}
func (timingMuter) ContainsTime([]string, time.Time) (bool, error) { return false, nil }

func TestOscarTimingRouteMuteSuppressesOnlyItsPath(t *testing.T) {
	now := time.Now().UTC()
	rows, _ := timingTestRows(now)
	rows = rows[:1]
	cfg, err := config.Load("route:\n  receiver: fallback\n  group_by: [alertname]\n  routes:\n  - receiver: team\n    matchers: [instance=\"a\"]\n    continue: true\n    mute_time_intervals: [quiet]\n  - receiver: team\n    matchers: [instance=\"a\"]\nreceivers:\n- name: fallback\n- name: team\ntime_intervals:\n- name: quiet\n  time_intervals:\n  - weekdays: [sunday]\n")
	require.NoError(t, err)
	route := dispatch.NewRoute(cfg.Route, nil)
	hash := notify.HashAlert(rows[0].a)
	lookups := 0
	source := &TimingSource{Integrations: map[string][]TimingIntegration{"team": {{Name: "webhook", Index: 0}}}, Muter: timingMuter{}, Lookup: func(string, *nflogpb.Receiver, []uint64, int) nflog.TimingLookup {
		lookups++
		return nflog.TimingLookup{Found: true, Timestamp: now, ExpiresAt: now.Add(24 * time.Hour), Firing: map[uint64]bool{hash: true}, Inspected: 1}
	}}
	steps := timingForPage(rows, route, source, now)[rows[0].fingerprint].RepeatSchedules
	require.Len(t, steps, 2)
	require.Equal(t, "suppressed", *steps[0].State)
	require.Equal(t, "estimated", *steps[1].State)
	require.Equal(t, 1, lookups)
}
