// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0

package v2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/app"
	"github.com/prometheus/alertmanager/featurecontrol"
	"github.com/prometheus/alertmanager/matcher/compat"
	"github.com/prometheus/alertmanager/oscarstate"
	"github.com/prometheus/alertmanager/oscarstate/memadapter"
	"github.com/prometheus/alertmanager/provider/mem"
)

type parityAction struct {
	Method, Path, Save string
	Body               json.RawMessage
	WaitMS             int    `json:"wait_ms"`
	ConfigReceiver     string `json:"config_receiver"`
	Restart            bool
}
type parityScenario struct {
	Observation string
	ID          string
	Actions     []parityAction
	Expected    struct {
		State, Receiver string
		Count           int
	}
	NoPut  bool `json:"no_put"`
	Target string
}
type parityCatalogue struct {
	SchemaVersion int `json:"schema_version"`
	Config        string
	GCIntervals   []string `json:"gc_intervals"`
	Queries       map[string]string
	FieldContract map[string]string `json:"field_contract"`
	Scenarios     []parityScenario
}
type parityNative struct {
	Fingerprint                 string
	Labels, Annotations         map[string]string
	StartsAt, EndsAt, UpdatedAt time.Time
	GeneratorURL                string
	Receivers                   []struct{ Name string }
	Status                      struct {
		State                            string
		SilencedBy, InhibitedBy, MutedBy []string
	}
}
type parityFixture struct {
	t         *testing.T
	catalogue parityCatalogue
	opts      app.Options
	runtime   *app.App
	feed      *oscarstate.Feed
	observer  *memadapter.Observer
	provider  *mem.Alerts
	base      time.Time
	variables map[string]string
	client    *http.Client
}

func parityEventually(t *testing.T, condition func() bool, timeout, interval time.Duration, message ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if condition() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met: %v", message)
		}
		time.Sleep(interval)
	}
}

// waitResolvedGC removes unrelated expired rows before exact snapshot checks.
func (f *parityFixture) waitResolvedGC() {
	f.t.Helper()
	parityEventually(f.t, func() bool {
		pending := f.observer.Snapshot(f.provider)
		for _, row := range pending.Alerts {
			if row.Alert.EndsAt.Before(time.Now()) {
				return false
			}
		}
		return true
	}, 3*time.Second, 10*time.Millisecond, "unrelated resolved source must be GC'd before exact snapshot assertion")
}

func (f *parityFixture) start() {
	f.t.Helper()
	f.feed = oscarstate.NewFeed(256, "")
	f.observer = memadapter.New(f.feed)
	f.opts.Registerer = prometheus.NewRegistry()
	f.opts.StateObserver = f.observer
	f.opts.ProbeHandler = func(p *mem.Alerts) http.Handler { f.provider = p; return http.NotFoundHandler() }
	var err error
	f.runtime, err = app.New(f.opts)
	require.NoError(f.t, err)
	require.NoError(f.t, f.runtime.Start())
	parityEventually(f.t, func() bool {
		r, e := f.client.Get("http://" + f.runtime.Addr() + "/-/ready")
		if e != nil {
			return false
		}
		defer r.Body.Close()
		return r.StatusCode == 200
	}, 5*time.Second, 10*time.Millisecond)
}
func (f *parityFixture) stop() {
	f.t.Helper()
	require.NoError(f.t, f.runtime.Stop(context.Background()))
}
func (f *parityFixture) request(method, path string, body []byte) []byte {
	f.t.Helper()
	req, err := http.NewRequest(method, "http://"+f.runtime.Addr()+path, bytes.NewReader(body))
	require.NoError(f.t, err)
	req.Header.Set("Content-Type", "application/json")
	res, err := f.client.Do(req)
	require.NoError(f.t, err)
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	require.NoError(f.t, err)
	require.Equal(f.t, 200, res.StatusCode, "%s %s: %s", method, path, data)
	return data
}
func (f *parityFixture) native(path string) []parityNative {
	f.t.Helper()
	var rows []parityNative
	require.NoError(f.t, json.Unmarshal(f.request("GET", path, nil), &rows))
	return rows
}
func (f *parityFixture) config(receiver string) {
	f.t.Helper()
	require.NoError(f.t, os.WriteFile(f.opts.ConfigFile, []byte(strings.ReplaceAll(f.catalogue.Config, "$receiver", receiver)), 0600))
}
func (f *parityFixture) expand(body []byte) []byte {
	var value any
	require.NoError(f.t, json.Unmarshal(body, &value))
	now := time.Now()
	var walk func(any) any
	walk = func(v any) any {
		switch v := v.(type) {
		case string:
			for prefix, base := range map[string]time.Time{"$base": f.base, "$now": now} {
				if strings.HasPrefix(v, prefix) {
					d, e := time.ParseDuration(strings.TrimPrefix(strings.TrimPrefix(v, prefix), "+"))
					require.NoError(f.t, e)
					return base.Add(d).UTC().Format(time.RFC3339Nano)
				}
			}
			return v
		case []any:
			for i, x := range v {
				v[i] = walk(x)
			}
			return v
		case map[string]any:
			for k, x := range v {
				v[k] = walk(x)
			}
			return v
		default:
			return v
		}
	}
	out, err := json.Marshal(walk(value))
	require.NoError(f.t, err)
	return out
}
func (f *parityFixture) action(a parityAction) {
	f.t.Helper()
	if a.WaitMS > 0 {
		time.Sleep(time.Duration(a.WaitMS) * time.Millisecond)
	}
	if a.ConfigReceiver != "" {
		f.config(a.ConfigReceiver)
	}
	if a.Restart {
		f.stop()
		f.start()
	}
	if a.Method != "" {
		path := a.Path
		for k, v := range f.variables {
			path = strings.ReplaceAll(path, "$"+k, v)
		}
		body := a.Body
		if len(body) > 0 {
			body = f.expand(body)
		}
		data := f.request(a.Method, path, body)
		if a.Save != "" {
			var result map[string]string
			require.NoError(f.t, json.Unmarshal(data, &result))
			require.NotEmpty(f.t, result["silenceID"])
			f.variables[a.Save] = result["silenceID"]
		}
	}
}
func newParityFixture(t *testing.T, c parityCatalogue, gc time.Duration) *parityFixture {
	dir := t.TempDir()
	logger := promslog.NewNopLogger()
	flags, err := featurecontrol.NewFlags(logger, "")
	require.NoError(t, err)
	compat.InitFromFlags(logger, flags)
	o := app.DefaultOptions()
	o.Logger = logger
	o.Flagger = flags
	o.ConfigFile = filepath.Join(dir, "alertmanager.yml")
	o.DataDir = dir
	o.AlertGCInterval = gc
	addrs := []string{"127.0.0.1:0"}
	systemd := false
	webconfig := ""
	o.WebConfig = &web.FlagConfig{WebListenAddresses: &addrs, WebSystemdSocket: &systemd, WebConfigFile: &webconfig}
	f := &parityFixture{t: t, catalogue: c, opts: o, base: time.Now(), variables: map[string]string{}, client: &http.Client{Timeout: 3 * time.Second}}
	f.config("proof-a")
	f.start()
	t.Cleanup(f.stop)
	return f
}
func parityTarget(rows []parityNative, target string) *parityNative {
	for i := range rows {
		if rows[i].Labels["instance"] == target {
			return &rows[i]
		}
	}
	return nil
}
func parityRaw(rows map[string]*alert.Alert, target string) *alert.Alert {
	for _, a := range rows {
		if string(a.Labels["instance"]) == target {
			return a
		}
	}
	return nil
}
func paritySameTime(t *testing.T, want, got time.Time, field string) {
	t.Helper()
	require.True(t, want.Truncate(time.Millisecond).Equal(got.Truncate(time.Millisecond)), "%s: raw=%s native=%s", field, want, got)
}
func parityFields(t *testing.T, n parityNative, a *alert.Alert) {
	t.Helper()
	require.NotNil(t, a, "missing raw alert %s", n.Fingerprint)
	require.Equal(t, a.Fingerprint().String(), n.Fingerprint)
	labels := map[string]string{}
	for k, v := range a.Labels {
		labels[string(k)] = string(v)
	}
	annotations := map[string]string{}
	for k, v := range a.Annotations {
		annotations[string(k)] = string(v)
	}
	require.Equal(t, labels, n.Labels)
	require.Equal(t, annotations, n.Annotations)
	paritySameTime(t, a.StartsAt, n.StartsAt, "startsAt")
	paritySameTime(t, a.UpdatedAt, n.UpdatedAt, "updatedAt")
	paritySameTime(t, a.EndsAt, n.EndsAt, "endsAt")
	require.Equal(t, a.GeneratorURL, n.GeneratorURL)
}

// parityMutationError validates feed evidence, including unchanged duplicate puts.
func parityMutationError(s parityScenario, target string, batches ...[]oscarstate.Change) error {
	for _, changes := range batches {
		for _, ch := range changes {
			if ch.Kind != oscarstate.Upsert {
				continue
			}
			if s.NoPut {
				return fmt.Errorf("unexpected Put for %s", s.ID)
			}
			if (s.ID == "inhibition-on" || s.ID == "inhibition-off") && ch.Fingerprint.String() == target {
				return fmt.Errorf("target must not be put by source transition %s", s.ID)
			}
		}
	}
	return nil
}

func TestOSCARStateParityMutationEvidence(t *testing.T) {
	for _, id := range []string{"inhibition-on", "inhibition-off", "silence-create"} {
		for _, position := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/batch%d", id, position), func(t *testing.T) {
				s := parityScenario{ID: id, NoPut: id == "silence-create"}
				feed := oscarstate.NewFeed(8, "evidence")
				cursor := feed.Cursor()
				a := alert.New(model.Alert{Labels: model.LabelSet{"instance": "target"}}, time.Now(), false)
				feed.Publish(oscarstate.Change{Kind: oscarstate.Upsert, Fingerprint: a.Fingerprint(), Alert: a})
				batch, err := feed.Read(cursor, 8)
				require.NoError(t, err)
				batches := [][]oscarstate.Change{nil, nil}
				batches[position] = batch.Changes
				require.Error(t, parityMutationError(s, a.Fingerprint().String(), batches...), "unchanged target upsert must be caught in either batch")
			})
		}
	}
	for _, id := range []string{"inhibition-on", "inhibition-off"} {
		require.NoError(t, parityMutationError(parityScenario{ID: id}, "000000000000002a", []oscarstate.Change{{Kind: oscarstate.Upsert, Fingerprint: 43}}, nil))
	}
}

// TestOSCARStateParityObsoleteClearGC stresses the exact-snapshot boundary
// with an unrelated resolved inhibition source and the native 1s GC ticker.
func TestOSCARStateParityObsoleteClearGC(t *testing.T) {
	data, err := os.ReadFile("../../oscarstate/testdata/scenarios.json")
	require.NoError(t, err)
	var c parityCatalogue
	require.NoError(t, json.Unmarshal(data, &c))
	f := newParityFixture(t, c, time.Second)
	selected := map[string]bool{"create": true, "refresh": true, "inhibition-on": true, "inhibition-off": true}
	var obsolete parityScenario
	for _, s := range c.Scenarios {
		if selected[s.ID] {
			for _, a := range s.Actions {
				f.action(a)
			}
		}
		if s.ID == "late-obsolete-resolve" {
			obsolete = s
		}
	}
	// This is the same barrier used by the complete catalogue runner.
	f.waitResolvedGC()
	before := f.native(c.Queries["all"])
	require.Len(t, before, 1)
	snapshot := f.observer.Snapshot(f.provider)
	require.Len(t, snapshot.Alerts, 1)
	for _, a := range obsolete.Actions {
		f.action(a)
	}
	require.Equal(t, before, f.native(c.Queries["all"]))
	require.Equal(t, snapshot, f.observer.Snapshot(f.provider))
}

// TestOSCARStateParity classifies raw-provider/API divergences. It does not fill a
// projection from GET and does not claim DuckDB or bounded-sweep parity.
func TestOSCARStateParity(t *testing.T) {
	data, err := os.ReadFile("../../oscarstate/testdata/scenarios.json")
	require.NoError(t, err)
	var c parityCatalogue
	require.NoError(t, json.Unmarshal(data, &c))
	require.Equal(t, 1, c.SchemaVersion)
	require.Equal(t, []string{"1s", "30m"}, c.GCIntervals)
	for _, field := range []string{"fingerprint", "labels", "annotations", "startsAt", "endsAt", "updatedAt", "generatorURL", "receivers", "status", "silencedBy", "inhibitedBy", "mutedBy", "membership"} {
		require.NotEmpty(t, c.FieldContract[field], "missing catalogue field contract for %s", field)
	}
	ids := map[string]bool{}
	for _, s := range c.Scenarios {
		require.NotEmpty(t, s.ID)
		require.False(t, ids[s.ID], "duplicate ID %s", s.ID)
		ids[s.ID] = true
	}
	for _, gcText := range c.GCIntervals {
		t.Run("gc="+gcText, func(t *testing.T) {
			gc, err := time.ParseDuration(gcText)
			require.NoError(t, err)
			f := newParityFixture(t, c, gc)
			snapshot := f.observer.Snapshot(f.provider)
			cursor := snapshot.Cursor
			raw := map[string]*alert.Alert{}
			require.Empty(t, snapshot.Alerts)
			seen := map[string]bool{}
			for _, s := range c.Scenarios {
				t.Run(s.ID, func(t *testing.T) {
					f.t = t
					target := s.Target
					if target == "" {
						target = "target"
					}
					if (s.ID == "late-obsolete-resolve" || s.ID == "gc") && gc <= time.Second {
						f.waitResolvedGC()
					}
					before := f.native(c.Queries["all"])
					if s.ID == "duplicate" || s.ID == "refresh" {
						previous := parityTarget(before, target)
						require.NotNil(t, previous)
						parityEventually(t, func() bool { return time.Now().Truncate(time.Millisecond).After(previous.UpdatedAt) }, time.Second, time.Millisecond, "advance beyond native JSON precision")
					}
					beforeRaw := f.observer.Snapshot(f.provider)
					for _, a := range s.Actions {
						f.action(a)
					}
					if s.ID == "source-restart" {
						require.NotEqual(t, cursor.Epoch, f.feed.Cursor().Epoch)
						_, err := f.feed.Read(cursor, 256)
						require.ErrorIs(t, err, oscarstate.ErrEpoch)
						snapshot = f.observer.Snapshot(f.provider)
						require.Empty(t, snapshot.Alerts)
						cursor = snapshot.Cursor
						raw = map[string]*alert.Alert{}
					}
					var rows []parityNative
					parityEventually(t, func() bool {
						rows = f.native(c.Queries["all"])
						if len(rows) != s.Expected.Count {
							return false
						}
						n := parityTarget(rows, target)
						if s.Expected.State == "absent" {
							return n == nil
						}
						return n != nil && n.Status.State == s.Expected.State
					}, 3*time.Second, 10*time.Millisecond, "missing native observation for %s", s.ID)
					batches := [][]oscarstate.Change{}
					consume := func() {
						batch, err := f.feed.Read(cursor, 256)
						require.NoError(t, err)
						batches = append(batches, batch.Changes)
						for _, ch := range batch.Changes {
							if ch.Kind == oscarstate.Delete {
								delete(raw, ch.Fingerprint.String())
							} else {
								raw[ch.Fingerprint.String()] = ch.Alert
							}
						}
						cursor = batch.Continue
					}
					consume() // The action's batch is retained alongside every reconciliation batch.
					parityEventually(t, func() bool {
						snapshot = f.observer.Snapshot(f.provider)
						consume()
						return snapshot.Cursor == cursor
					}, 3*time.Second, 10*time.Millisecond, "fixed snapshot and replay cursor must agree for every ID")
					require.Len(t, raw, len(snapshot.Alerts))
					for _, a := range snapshot.Alerts {
						require.Equal(t, a.Alert, raw[a.Fingerprint.String()])
					}
					targetFP := ""
					if previous := parityTarget(before, "target"); previous != nil {
						targetFP = previous.Fingerprint
					}
					require.NoError(t, parityMutationError(s, targetFP, batches...))

					for _, n := range rows {
						parityFields(t, n, raw[n.Fingerprint])
						require.Empty(t, n.Status.MutedBy)
						require.Equal(t, []struct{ Name string }{{s.Expected.Receiver}}, n.Receivers)
						if n.Labels["instance"] == target {
							switch s.ID {
							case "silence-create", "silence-start":
								require.Equal(t, []string{f.variables["silence"]}, n.Status.SilencedBy)
								require.Empty(t, n.Status.InhibitedBy)
							case "inhibition-on":
								source := parityTarget(rows, "source")
								require.NotNil(t, source)
								require.Equal(t, []string{source.Fingerprint}, n.Status.InhibitedBy)
								require.Empty(t, n.Status.SilencedBy)
							default:
								require.Empty(t, n.Status.SilencedBy)
								require.Empty(t, n.Status.InhibitedBy)
							}
						}
					}
					if s.ID == "inhibition-on" || s.ID == "inhibition-off" {
						oldTarget := parityTarget(before, "target")
						require.NotNil(t, oldTarget)
						for _, row := range beforeRaw.Alerts {
							if row.Alert.Labels["instance"] == "target" {
								require.Equal(t, row.Alert, parityRaw(raw, "target"))
							}
						}
					}
					if s.ID == "refresh" || s.ID == "duplicate" {
						n := parityTarget(rows, target)
						previous := parityTarget(before, target)
						require.Equal(t, "refreshed", n.Annotations["summary"])
						require.Equal(t, "https://example.invalid/refreshed", n.GeneratorURL)
						require.True(t, n.UpdatedAt.After(previous.UpdatedAt))
						require.Greater(t, cursor.Sequence, beforeRaw.Cursor.Sequence)
					}
					if s.ID == "late-obsolete-resolve" {
						require.Equal(t, before, rows)
						afterRaw := f.observer.Snapshot(f.provider)
						require.Equal(t, beforeRaw.Cursor, afterRaw.Cursor)
						require.ElementsMatch(t, beforeRaw.Alerts, afterRaw.Alerts)
					}
					if s.ID == "explicit-resolve" || s.ID == "timeout" {
						require.Nil(t, parityTarget(rows, target))
						if gc == 30*time.Minute {
							require.NotNil(t, parityRaw(raw, target), "native disappears before feed delete at production GC")
						}
					}
					if s.ID == "gc" {
						if gc <= time.Second {
							require.Empty(t, raw)
						} else {
							require.NotEmpty(t, raw)
						}
					}
					for name, path := range c.Queries {
						filtered := f.native(path)
						expected := []parityNative{}
						for _, n := range rows {
							include := false
							switch name {
							case "all":
								include = true
							case "target":
								include = n.Labels["instance"] == "target"
							case "active":
								include = n.Status.State == "active"
							case "unprocessed":
								include = n.Status.State == "unprocessed"
							case "receiver_a":
								include = n.Receivers[0].Name == "proof-a"
							case "receiver_b":
								include = n.Receivers[0].Name == "proof-b"
							default:
								t.Fatalf("unhandled catalogue query %s", name)
							}
							if include {
								expected = append(expected, n)
							}
						}
						require.Equal(t, expected, filtered, "exact filtered set for %s", name)
					}
					require.NotEmpty(t, s.Observation, "missing field/invalidation observation for catalogue ID %s", s.ID)
					t.Log(s.Observation)
					seen[s.ID] = true
					t.Logf("%s: raw-owned fields compared; native derived state=%s receiver=%s; raw=%d native=%d", s.ID, s.Expected.State, s.Expected.Receiver, len(raw), len(rows))
				})
				f.t = t
				if t.Failed() {
					break
				}
			}
			require.Equal(t, ids, seen, "every catalogue ID must be observed")
		})
	}
}
