// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	v2 "github.com/prometheus/alertmanager/api/v2"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/notify/webhook"
	"github.com/prometheus/alertmanager/provider/mem"
)

type recoveryFixture struct {
	terminalFixtureJournal
	epoch     atomic.Uint64
	receipts  atomic.Bool
	candidate func(*alert.Alert) bool
	classify  func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error)
}

func (j *recoveryFixture) RecoveryState() (uint64, bool) { return j.epoch.Load(), j.receipts.Load() }
func (j *recoveryFixture) MayHaveEpisode(_ uint64, s *alert.Alert) bool {
	return j.candidate != nil && j.candidate(s)
}
func (j *recoveryFixture) ClassifyResident(ctx context.Context, epoch uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
	return j.classify(ctx, epoch, s)
}

func restoredFixture(t *testing.T, s *alert.Alert) v2.EpisodeProjection {
	t.Helper()
	var p v2.EpisodeProjection
	require.NoError(t, json.Unmarshal([]byte(fmt.Sprintf(`{"episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111111","episode_id":"22222222-2222-4222-8222-222222222222","generation":1,"variant_revision":1},"native_variant":{"fingerprint":%q,"starts_at":%q},"lifecycle_seq":1,"active_since":%q,"state":"firing","source_severity":"major","floor":"critical","severity_revision":3}`, s.Fingerprint().String(), s.StartsAt.Format(time.RFC3339Nano), s.StartsAt.Format(time.RFC3339Nano))), &p))
	return p
}

// Acquire the resident-owned local token when exercising the final publication predicate directly.
func fixtureDirectPass(t *testing.T, a *nativeActions, s *alert.Alert, epoch uint64) *v2.OrdinaryPass {
	t.Helper()
	key := residentKey(s.ManagedMember.Episode, s)
	token := &v2.DirectContact{}
	require.True(t, a.ChangeDirectContact(key, nil, token))
	return &v2.OrdinaryPass{Epoch: epoch, Contact: token, Finish: func(conclusive bool) {
		if conclusive {
			a.ChangeDirectContact(key, token, nil)
		}
	}}
}

func TestOscarActionFactoryCommissioningAndReceiptLoss(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			r := newTestReloader(t)
			t.Cleanup(func() { _ = r.stop() })
			opts := testOptions(t)
			owner, actions := configureNativeActions(opts, nil, r.logger)
			require.Nil(t, owner.Dispatch)
			require.Nil(t, actions)
			opts.ActionOwner.Enabled = true
			opts.ActionOwner.Scheme = scheme
			tlsServer := httptest.NewTLSServer(nil)
			t.Cleanup(tlsServer.Close)
			opts.ActionOwner.CAFile = filepath.Join(t.TempDir(), "ca.pem")
			require.NoError(t, os.WriteFile(opts.ActionOwner.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0600))
			opts.ConversionCallbackKey = []byte(strings.Repeat("k", 32))
			owner, actions = configureNativeActions(opts, nil, r.logger)
			require.Same(t, actions, owner.Dispatch)
			opts.ActionOwner.Dispatch = actions
			_, injected := configureNativeActions(opts, nil, r.logger)
			require.Same(t, actions, injected)
			j := &recoveryFixture{classify: func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error) { return nil, nil }}
			require.NoError(t, actions.Bind(j))
			r.actions = actions
			cred := filepath.Join(t.TempDir(), "callback")
			require.NoError(t, os.WriteFile(cred, opts.ConversionCallbackKey, 0o600))
			tls := "insecure_skip_verify: true"
			if scheme == "https" {
				tls = "ca_file: " + opts.ActionOwner.CAFile
			}
			yaml := fmt.Sprintf("route:\n  receiver: default\n  group_wait: 1h\nreceivers:\n- name: default\n  webhook_configs:\n  - url: %s://alertmanager-middleware:9400%s\n    send_resolved: true\n    http_config:\n      tls_config:\n        %s\n      follow_redirects: false\n      authorization:\n        type: Bearer\n        credentials_file: %s\n", scheme, alert.NativeCallbackPath, tls, cred)
			load := func(input string) *config.Config { c, e := config.Load(input); require.NoError(t, e); return c }
			require.NoError(t, r.reload(load(strings.Replace(yaml, "send_resolved: true", "send_resolved: false", 1))))
			require.Zero(t, actions.Version())
			require.NoError(t, r.reload(load(yaml)))
			g := actions.snapshot()
			require.NotNil(t, g)
			j.epoch.Store(1)
			now := time.Now()
			s := alert.New(model.Alert{Labels: model.LabelSet{"host": "one", "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
			actions.ObserveSource("", s, false, false)
			require.Eventually(t, func() bool { return actions.ReadView(s) != nil }, 5*time.Second, time.Millisecond)
			require.Zero(t, actions.Version())
			wire := s.NotificationCopy(now)
			active := map[*alert.Alert]bool{wire: true}
			c := ordinaryContact{legacy: true, pass: fixtureDirectPass(t, actions, s, j.epoch.Load()), contact: plannedContact{integration: actionIntegration{canonical: true}}}
			check := func() bool {
				return actions.finalPublication(g, []*alert.Alert{wire}, []ordinaryContact{c}, active, entryTransition{ctx: t.Context()}, func() {})
			}
			require.True(t, check(), "only a proven untracked pass can continue before commissioning")
			j.receipts.Store(true)
			require.Equal(t, 1, actions.Version())
			require.False(t, check(), "an earlier unsigned pass cannot enter after commissioning")
			j.receipts.Store(false)
			require.Zero(t, actions.Version())
			c.pass = nil
			c.legacy = false
			require.False(t, check(), "a tracked signed entry cannot downgrade")
			j.epoch.Store(0)
			c.pass = &v2.OrdinaryPass{}
			c.legacy = true
			require.False(t, check(), "there is no negative proof after lease loss")
		})
	}
}

func TestOscarActionRecoveryPublishesLateInhibitorBeforeEntry(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	newSource := func(host, cluster, severity string) *alert.Alert {
		return alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "cluster": model.LabelValue(cluster), "severity": model.LabelValue(severity)}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	}
	b, c, late := newSource("B", "one", "minor"), newSource("C", "two", "minor"), newSource("late", "one", "major")
	p := restoredFixture(t, late)
	started, release := make(chan struct{}), make(chan struct{})
	var stale atomic.Bool
	var calls atomic.Int64
	j := &recoveryFixture{candidate: func(s *alert.Alert) bool {
		i, err := strconv.Atoi(string(s.Labels["host"]))
		return s == late || err == nil && i < 300
	}, classify: func(ctx context.Context, epoch uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
		calls.Add(1)
		if s == late {
			if stale.CompareAndSwap(false, true) {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return &p, nil
		}
		return nil, nil
	}}
	actions := newNativeActions(nil, nil, r.logger)
	r.actions = actions
	require.NoError(t, actions.Bind(j))
	actions.ObserveSource("", b, false, true)
	actions.ObserveSource("", c, false, true)
	for i := range 4096 {
		actions.ObserveSource("", newSource(fmt.Sprint(i), "unrelated", "info"), false, true)
	}
	actions.ObserveSource("", late, false, true)
	cfg, e := config.Load("route:\n  receiver: base\n  group_wait: 1h\n  routes:\n  - receiver: escalated\n    matchers: ['severity=critical']\nreceivers:\n- name: base\n- name: escalated\ninhibit_rules:\n- source_matchers: ['severity=critical']\n  target_matchers: ['severity=minor']\n  equal: [cluster]\n")
	require.NoError(t, e)
	require.NoError(t, r.reload(cfg))
	j.epoch.Store(1)
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Fatal("late floor not inspected")
	}
	g := actions.snapshot()
	enter := func(g *actionGraph, m *alert.Alert) bool {
		pass := fixtureDirectPass(t, actions, m, j.epoch.Load())
		defer pass.Finish(true)
		return actions.finalPublication(g, []*alert.Alert{m}, []ordinaryContact{{pass: pass}}, map[*alert.Alert]bool{m: true}, entryTransition{ctx: t.Context()}, func() {})
	}
	require.False(t, enter(g, b))
	require.True(t, enter(g, c), "unrelated delivery remains available during a blocked indexed proof")
	close(release)
	require.Eventually(t, func() bool { return actions.Version() == 1 && actions.ReadView(late) != nil }, 10*time.Second, time.Millisecond)
	require.Equal(t, model.LabelValue("critical"), actions.ReadView(late).Labels["severity"])
	groups, _, err := r.groups(t.Context(), func(*dispatch.Route) bool { return true }, func(m *alert.Alert, _ time.Time) (alert.AlertStatus, bool) {
		return alert.AlertStatus{}, m.ProviderSource() == late
	})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "escalated", groups[0].Receiver)
	require.False(t, enter(g, b))
	require.True(t, enter(g, c))
	before := calls.Load()
	for range 100 {
		require.True(t, enter(g, c))
	}
	require.Equal(t, before, calls.Load(), "provider entry makes no inventory or classification read")
	actions.InvalidateSource(late)
	require.False(t, enter(g, b))
	require.True(t, enter(g, c))
	require.NoError(t, r.reload(cfg))
	require.False(t, enter(g, c), "an old graph cannot authorize a new entry")
	require.Eventually(t, func() bool { return actions.Version() == 1 }, 15*time.Second, time.Millisecond)
	require.False(t, enter(actions.snapshot(), b))
	j.epoch.Store(2)
	require.False(t, enter(actions.snapshot(), c), "takeover fences the old publication synchronously")
}

func TestOscarActionManagedReplacementDuringRecoveryRejectsLateGCAndSubscriber(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	owner := strings.Repeat("e", 64)
	member := func(host string, gen int64) *alert.Alert {
		s := alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
		s.ManagedReceiver = true
		s.ManagedMember = alert.ManagedMembership{Episode: owner, Generation: gen}
		return s
	}
	old, next := member("old", 1), member("new", 2)
	oldRow, nextRow := restoredFixture(t, old), restoredFixture(t, next)
	nextRow.EpisodeRef.VariantRevision = 2
	nextRow.LifecycleSeq++
	started, release := make(chan struct{}), make(chan struct{})
	j := &recoveryFixture{candidate: func(*alert.Alert) bool { return true }, classify: func(ctx context.Context, _ uint64, s *alert.Alert) (*v2.EpisodeProjection, error) {
		if s == old {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &oldRow, nil
		}
		return &nextRow, nil
	}}
	j.epoch.Store(1)
	a := newNativeActions(nil, nil, r.logger)
	r.actions = a
	require.NoError(t, a.Bind(j))
	a.ObserveSource(owner, old, false, true)
	require.NoError(t, r.reload(mustConfig(t)))
	g := a.snapshot()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("initial proof did not begin")
	}
	a.ObserveSource(owner, next, false, true)
	a.ObserveSource(owner, old, true, true)
	close(release)
	require.Eventually(t, func() bool { return a.ReadView(next) != nil }, 5*time.Second, time.Millisecond)
	require.Nil(t, a.ReadView(old))
	require.Equal(t, model.LabelValue("critical"), a.ReadView(next).Labels["severity"])
	a.graphView(g, old, true, func(*alert.Alert) { t.Fatal("retired subscriber overwrote the successor") })
	require.NoError(t, r.reload(mustConfig(t)))
	a.graphView(g, next, false, func(*alert.Alert) { t.Fatal("cancelled graph subscriber ran") })
	a.ObserveSource(owner, nil, true, true)
	require.Nil(t, a.ReadView(next))
}

func TestOscarActionRecoveryInstallKeepsLaterRevisionAcrossReload(t *testing.T) {
	r := newTestReloader(t)
	t.Cleanup(func() { _ = r.stop() })
	now := time.Now()
	src := alert.New(model.Alert{Labels: model.LabelSet{"host": "one", "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	target := alert.New(model.Alert{Labels: model.LabelSet{"host": "one", "severity": "minor"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)
	current := restoredFixture(t, src)
	stale := current
	stale.SeverityRevision--
	stale.Floor = ""
	var old atomic.Bool
	j := &recoveryFixture{candidate: func(s *alert.Alert) bool { return s == src }, classify: func(context.Context, uint64, *alert.Alert) (*v2.EpisodeProjection, error) {
		if old.Load() {
			return &stale, nil
		}
		return &current, nil
	}}
	a := newNativeActions(nil, nil, r.logger)
	r.actions = a
	require.NoError(t, a.Bind(j))
	a.ObserveSource("", src, false, true)
	a.ObserveSource("", target, false, true)
	cfg, err := config.Load("route:\n  receiver: base\nreceivers:\n- name: base\ninhibit_rules:\n- source_matchers: ['severity=critical']\n  target_matchers: ['severity=minor']\n  equal: [host]\n")
	require.NoError(t, err)
	j.epoch.Store(1)
	require.NoError(t, r.reload(cfg))
	require.Eventually(t, func() bool { v := a.ReadView(src); return v != nil && v.Labels["severity"] == "critical" }, 5*time.Second, time.Millisecond)
	old.Store(true)
	require.NoError(t, r.reload(cfg))
	require.Eventually(t, func() bool { return a.Version() == 1 }, 5*time.Second, time.Millisecond)
	require.Never(t, func() bool {
		g := a.snapshot()
		pass := fixtureDirectPass(t, a, target, j.epoch.Load())
		defer pass.Finish(true)
		return a.finalPublication(g, []*alert.Alert{target}, []ordinaryContact{{pass: pass}}, map[*alert.Alert]bool{target: true}, entryTransition{ctx: t.Context()}, func() {})
	}, 100*time.Millisecond, time.Millisecond)
}

// Keep this phase's group silent until a complete native suppression turn has finished.
// Both the group membership and the suppression count come from the running app.
func silenceFixtureCohort(t *testing.T, a *App, registry *prometheus.Registry, label, value string) func(string, []*alert.Alert) {
	t.Helper()
	base := "http://" + a.Addr()
	mutate := func(method, path, body string) []byte {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Oscar-Silence-Mutation-Key", string(a.opts.SilenceMutationKey))
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode, string(data))
		return data
	}
	now := time.Now().UTC()
	body := fmt.Sprintf(`{"matchers":[{"name":%q,"value":%q,"isRegex":false}],"startsAt":%q,"endsAt":%q,"createdBy":"cohort fixture","comment":"assemble one native group"}`, label, value, now.Add(-time.Minute).Format(time.RFC3339Nano), now.Add(2*time.Hour).Format(time.RFC3339Nano))
	var sil struct {
		ID string `json:"silenceID"`
	}
	require.NoError(t, json.Unmarshal(mutate(http.MethodPost, "/api/v2/silences", body), &sil))
	require.NotEmpty(t, sil.ID)
	count := func() float64 {
		families, err := registry.Gather()
		if err != nil {
			return -1
		}
		for _, family := range families {
			if family.GetName() != "alertmanager_notifications_suppressed_total" {
				continue
			}
			for _, metric := range family.Metric {
				for _, pair := range metric.Label {
					if pair.GetName() == "reason" && pair.GetValue() == "silence" {
						return metric.Counter.GetValue()
					}
				}
			}
		}
		return 0
	}
	return func(receiver string, expected []*alert.Alert) {
		t.Helper()
		want := map[string]bool{}
		for _, s := range expected {
			want[s.Fingerprint().String()] = true
		}
		require.Len(t, want, len(expected))
		q := url.Values{"receiver": {receiver}, "filter": {fmt.Sprintf("%s=%q", label, value)}}
		require.Eventually(t, func() bool {
			res, err := http.Get(base + "/api/v2/alerts/groups?" + q.Encode())
			if err != nil {
				return false
			}
			defer res.Body.Close()
			var groups []struct {
				Alerts []struct {
					Fingerprint string
					Status      struct{ SilencedBy []string }
				}
			}
			if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&groups) != nil || len(groups) != 1 || len(groups[0].Alerts) != len(want) {
				return false
			}
			seen := map[string]bool{}
			for _, m := range groups[0].Alerts {
				if !want[m.Fingerprint] || seen[m.Fingerprint] || !slices.Contains(m.Status.SilencedBy, sil.ID) {
					return false
				}
				seen[m.Fingerprint] = true
			}
			return true
		}, 2*time.Minute, 250*time.Millisecond)
		// Only this receiver/group matches the phase's one active silence.
		// MuteStage.Exec adds len(muted) once after its full filter loop.
		// Flushes run sequentially. At this baseline at most one earlier
		// partial snapshot can still add to the counter, by at most N-1.
		// Another N silenced members therefore includes a complete turn.
		baseline := count()
		require.GreaterOrEqual(t, baseline, float64(0))
		require.Eventually(t, func() bool { return count() >= baseline+float64(len(want)) }, 2*time.Minute, 100*time.Millisecond)
		mutate(http.MethodDelete, "/api/v2/silence/"+sil.ID, "")
	}
}

// Run normal setup (including provider replay, owner maintenance, graph dispatch,
// signed webhook encoding and settlement). Only TCP dialing goes to the fixture.
func TestOscarActionCommissioningThroughAppAndProvider(t *testing.T) {
	callbackKey := []byte(strings.Repeat("c", 32))
	storeKey := strings.Repeat("j", 32)
	var enabled, large atomic.Bool
	var uncommissionedRenewals atomic.Int32
	longName := strings.Repeat("L", 4096)
	type observation struct {
		entered    time.Time
		path       string
		signed     bool
		hosts      []string
		deliveries []string
	}
	observed := make(chan observation, 256)
	settled := make(chan string, 256)
	var mu sync.Mutex
	var leaseExpiry time.Time
	rows := map[string]map[string]any{}
	tokens := map[string]string{}
	claims := map[string]string{}
	type fixtureContact struct {
		scope, targetKey, delivery, receiver string
		repeat                               time.Duration
	}
	contacts := map[string]fixtureContact{}
	pending := map[string]string{}
	nextEligible := map[string]time.Time{}
	confirmed := map[string]time.Time{}
	longCommands := map[string]int{}
	var longSettled int
	var earlyCovered atomic.Int32
	var admissions atomic.Int32
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived := time.Now()
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if r.URL.Path == alert.NativeCallbackPath || r.URL.Path == "/direct" || r.URL.Path == "/long" {
			var msg webhook.Message
			if err := json.Unmarshal(raw, &msg); err != nil {
				t.Error(err)
				return
			}
			item := observation{entered: arrived, path: r.URL.Path, signed: r.Header.Get("X-Oscar-Native-Signature") != ""}
			for _, a := range msg.Alerts {
				item.hosts = append(item.hosts, a.Labels["host"])
			}
			if item.signed {
				headers, err := alert.NativeDeliveryHeaders(raw, "team", r.URL.RequestURI(), callbackKey)
				if err != nil || headers["X-Oscar-Native-Signature"] != r.Header.Get("X-Oscar-Native-Signature") || len(msg.NativeDeliveries) != len(msg.Alerts) {
					t.Error("signed callback does not match exact body/members")
					w.WriteHeader(403)
					return
				}
				mu.Lock()
				for n, claim := range msg.NativeDeliveries {
					id := claim.Delivery.DeliveryID
					if claim.Index != n || claims[id] != msg.Alerts[n].Fingerprint || claim.Delivery.NativeVariant.Fingerprint != msg.Alerts[n].Fingerprint {
						t.Errorf("unclaimed webhook body member %d", n)
					}
					item.deliveries = append(item.deliveries, id)
				}
				mu.Unlock()
			} else if len(msg.NativeDeliveries) != 0 {
				t.Error("unsigned callback contains delivery claims")
			}
			observed <- item
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+storeKey {
			w.WriteHeader(401)
			return
		}
		if len(raw) > 256<<10 {
			t.Errorf("oversized private request: %d", len(raw))
			w.WriteHeader(413)
			return
		}
		var cmd map[string]any
		if err := json.Unmarshal(raw, &cmd); err != nil {
			w.WriteHeader(400)
			return
		}
		if large.Load() {
			time.Sleep(8 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		var response any
		switch filepath.Base(r.URL.Path) {
		case "acquire-authority", "renew-authority":
			leaseExpiry = time.Now().UTC().Add(30 * time.Second)
			lease := map[string]any{"protocol": "native-action-store-v1", "terminal_observations": 2, "recovery_selectors": 1, "ordinary_cohort": 1, "recipient_binding": 2, "recipient_key": strings.Repeat("a", 64), "authority_id": cmd["authority_id"], "owner_id": cmd["owner_id"], "epoch": 1, "expires_at": leaseExpiry, "renew_seconds": 10}
			if enabled.Load() {
				lease["native_delivery_receipts"] = 1
			} else {
				uncommissionedRenewals.Add(1)
			}
			response = lease
		case "recover":
			response = []any{}
			if cmd["projection"] == "source" {
				if p := rows[fmt.Sprint(cmd["fingerprint"])]; p != nil {
					response = []any{p}
				}
			}
		case "project-episode":
			p := cmd["update"].(map[string]any)
			fp := p["native_variant"].(map[string]any)["fingerprint"].(string)
			p["id"] = p["episode_ref"].(map[string]any)["episode_id"]
			rows[fp] = p
			response = p
		case "inspect-cohort", "admit-cohort":
			command := filepath.Base(r.URL.Path)
			var issued bool
			var results []any
			for n, value := range cmd["members"].([]any) {
				m := value.(map[string]any)
				id := m["operation_id"].(string)
				target := m["target"].(map[string]any)
				receiver := target["receiver_id"].(string)
				if n == 0 && receiver == longName {
					longCommands[command]++
				}
				fields, _ := json.Marshal([]any{receiver, target["integration_digest"], []any{}})
				key := fmt.Sprintf("%x", sha256.Sum256(fields))
				scope := m["row_id"].(string) + "/" + key
				reply := map[string]any{"operation_id": id}
				results = append(results, reply)
				switch {
				case pending[scope] != "":
					reply["state"] = "held"
				case time.Now().Before(nextEligible[scope]):
					reply["state"] = "covered"
					if large.Load() && target["repeat_interval_us"].(float64) == float64((180*time.Second).Microseconds()) {
						earlyCovered.Add(1)
					}
				case command == "inspect-cohort":
					reply["state"] = "due"
				default:
					issued = true
					token := strings.ReplaceAll(id, "-", "") + strings.Repeat("0", 32)
					delivery := uuid.NewSHA1(uuid.MustParse(id), []byte(key)).String()
					pending[scope], tokens[id] = id, token
					contacts[id] = fixtureContact{scope, key, delivery, receiver, time.Duration(target["repeat_interval_us"].(float64)) * time.Microsecond}
					claims[delivery] = m["native_variant"].(map[string]any)["fingerprint"].(string)
					reply["state"], reply["entry_token"], reply["target_key"], reply["target"] = "entered", token, key, target
					reply["permit_expires_at"], reply["lease_expires_at"] = time.Now().Add(30*time.Second), leaseExpiry
				}
			}
			if issued && large.Load() {
				admissions.Add(1)
			}
			response = results
		case "settle-cohort":
			var ids []string
			for _, value := range cmd["members"].([]any) {
				m := value.(map[string]any)
				id := m["operation_id"].(string)
				c := contacts[id]
				if tokens[id] != m["entry_token"] || c.targetKey != m["target_key"] || pending[c.scope] != id {
					t.Error("settlement lost original token")
					w.WriteHeader(409)
					return
				}
				ids = append(ids, id)
				outcome := m["receipt"].(map[string]any)["outcome"].(string)
				if outcome == "confirmed" {
					deadline := time.Now().Add(c.repeat)
					confirmed[c.delivery], nextEligible[c.scope] = deadline, deadline
					if c.receiver == longName {
						longSettled++
					}
				}
				if outcome != "unknown" {
					delete(pending, c.scope)
				}
				select {
				case settled <- outcome:
				default:
				}
			}
			response = ids
		default:
			t.Errorf("unexpected private command %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		encoded, err := json.Marshal(response)
		if err != nil || len(encoded) > 2<<20 {
			t.Errorf("invalid private fixture response size %d: %v", len(encoded), err)
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(encoded)
	}))
	t.Cleanup(authority.Close)
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "alertmanager-middleware:9400" && address != "direct.example:80" {
			return nil, fmt.Errorf("unexpected endpoint %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, authority.Listener.Addr().String())
	}
	opts := testOptions(t)
	opts.DispatchStartDelay = 0
	opts.ConversionCallbackKey = callbackKey
	opts.SilenceMutationKey = []byte(strings.Repeat("s", 32))
	write := func(name, value string) string {
		path := filepath.Join(t.TempDir(), name)
		require.NoError(t, os.WriteFile(path, []byte(value), 0600))
		return path
	}
	opts.ActionOwner.Scheme = "http"
	opts.ActionOwner.StoreKeyFile = write("store", storeKey)
	opts.ActionOwner.OperatorKeyFile = write("operator", strings.Repeat("o", 32))
	opts.ActionOwner.PolicyKeyFile = write("policy", strings.Repeat("p", 32))
	cred := write("callback", string(callbackKey))
	yaml := fmt.Sprintf("route:\n  receiver: team\n  group_by: [host]\n  group_wait: 50ms\n  group_interval: 200ms\n  repeat_interval: 2s\nreceivers:\n- name: team\n  webhook_configs:\n  - url: http://alertmanager-middleware:9400%s\n    send_resolved: true\n    http_config:\n      follow_redirects: false\n      tls_config:\n        insecure_skip_verify: true\n      authorization:\n        type: Bearer\n        credentials_file: %s\n", alert.NativeCallbackPath, cred)
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(yaml), 0600))
	capability := func(a *App) bool {
		resp, err := http.Get("http://" + a.Addr() + "/api/v2/oscar/fingerprint-conversion-capability")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var value map[string]any
		return json.NewDecoder(resp.Body).Decode(&value) == nil && value["native_action_contract"] == "native-actions-v1"
	}
	off, err := newWithActionDialer(opts, dial)
	require.NoError(t, err)
	require.NoError(t, off.Start())
	require.False(t, capability(off))
	require.NoError(t, off.Stop(t.Context()))
	registry := prometheus.NewRegistry()
	opts.Registerer = registry
	opts.ActionOwner.Enabled = true
	var provider *mem.Alerts
	opts.ProbeHandler = func(p *mem.Alerts) http.Handler { provider = p; return http.NotFoundHandler() }
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(strings.Replace(yaml, "send_resolved: true", "send_resolved: false", 1)), 0600))
	instance, err := newWithActionDialer(opts, dial)
	require.NoError(t, err)
	t.Cleanup(func() { _ = instance.Stop(context.Background()) })
	require.NoError(t, instance.Start())
	require.False(t, capability(instance))
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(yaml), 0600))
	require.NoError(t, instance.Reload())
	send := func(host string) {
		now := time.Now()
		require.NoError(t, provider.Put(t.Context(), alert.New(model.Alert{Labels: model.LabelSet{"host": model.LabelValue(host), "severity": "major"}, StartsAt: now, EndsAt: now.Add(time.Hour)}, now, false)))
	}
	next := func(host string, signed bool) {
		t.Helper()
		deadline := time.After(18 * time.Second)
		for {
			select {
			case m := <-observed:
				if slices.Contains(m.hosts, host) {
					require.Equal(t, signed, m.signed)
					return
				}
			case <-deadline:
				t.Fatalf("missing %s signed=%t", host, signed)
			}
		}
	}
	send("legacy")
	next("legacy", false)
	require.False(t, capability(instance))
	enabled.Store(true)
	require.Eventually(t, func() bool { return capability(instance) }, 15*time.Second, 100*time.Millisecond)
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(strings.Replace(yaml, "send_resolved: true", "send_resolved: false", 1)), 0600))
	require.ErrorContains(t, instance.Reload(), "active native action graph cannot switch to unsupported receivers")
	require.True(t, capability(instance), "the rejected reload preserves the supported live graph")
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(yaml), 0600))
	require.NoError(t, instance.Reload())
	require.Eventually(t, func() bool { return capability(instance) }, 5*time.Second, 50*time.Millisecond)
	send("tracked")
	next("tracked", true)
	require.Eventually(t, func() bool {
		select {
		case s := <-settled:
			return s == "confirmed"
		default:
			return false
		}
	}, time.Second, 5*time.Millisecond)
	enabled.Store(false)
	require.Eventually(t, func() bool { return !capability(instance) }, 15*time.Second, 100*time.Millisecond)
	send("fresh")
	next("fresh", false)
	require.Never(t, func() bool {
		select {
		case m := <-observed:
			return !m.signed && slices.Contains(m.hosts, "tracked")
		default:
			return false
		}
	}, 3*time.Second, 10*time.Millisecond)
	// Give the dispatcher one coherent native group and an independent, longer
	// sibling clock. Each private command now consumes one simulated 8ms RTT.
	enabled.Store(true)
	require.Eventually(t, func() bool { return capability(instance) }, 15*time.Second, 100*time.Millisecond)
	bigConfig := strings.Replace(yaml, "group_by: [host]", "group_by: [batch]", 1)
	bigConfig = strings.Replace(bigConfig, "group_wait: 50ms", "group_wait: 5s", 1)
	bigConfig = strings.Replace(bigConfig, "group_interval: 200ms", "group_interval: 90s", 1)
	bigConfig = strings.Replace(bigConfig, "repeat_interval: 2s", "repeat_interval: 1h\n  routes:\n  - receiver: team\n    matchers: ['batch=large']\n    repeat_interval: 180s", 1)
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(bigConfig), 0600))
	require.NoError(t, instance.Reload())
	require.Eventually(t, func() bool { return capability(instance) }, 5*time.Second, 20*time.Millisecond)
	large.Store(true)
	bulk := make([]*alert.Alert, 4109)
	member := func(clock time.Time, host, batch string, useLongReceiver bool) *alert.Alert {
		labels := model.LabelSet{"host": model.LabelValue(host), "batch": model.LabelValue(batch), "severity": "major"}
		if useLongReceiver {
			labels["long_receiver"] = "yes"
		}
		return alert.New(model.Alert{Labels: labels, StartsAt: clock, EndsAt: clock.Add(time.Hour)}, clock, false)
	}
	sibling := member(time.Now(), "clock-sibling", "sibling", false)
	require.NoError(t, provider.Put(t.Context(), sibling))
	next("clock-sibling", true)
	siblingTiming := func() string {
		filter := url.QueryEscape(`{"items":[{"field":"fingerprint","operator":"equals","value":"` + sibling.Fingerprint().String() + `"}]}`)
		resp, err := http.Get("http://" + instance.Addr() + "/api/v2/oscar/alerts/page?grid_filter=" + filter)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		var page struct {
			Timing map[string]struct {
				Steps []struct {
					Next string `json:"next_repeat_eligible_at"`
				} `json:"repeat_schedules"`
			} `json:"timing_by_fingerprint"`
		}
		if json.NewDecoder(resp.Body).Decode(&page) != nil {
			return ""
		}
		steps := page.Timing[sibling.Fingerprint().String()].Steps
		if len(steps) != 1 {
			return ""
		}
		return steps[0].Next
	}
	require.Eventually(t, func() bool { return siblingTiming() != "" }, 3*time.Second, 25*time.Millisecond)
	before := siblingTiming()
	releaseBulk := silenceFixtureCohort(t, instance, registry, "batch", "large")
	bulkStart := time.Now()
	for n := range bulk {
		bulk[n] = member(bulkStart, fmt.Sprintf("bulk-%05d", n), "large", n < 64)
	}
	require.NoError(t, provider.Put(t.Context(), bulk...))
	releaseBulk("team", bulk)
	priorDeadlines := map[string]time.Time{}
	previous := map[string]bool{}
	for turn := 0; turn < 2; turn++ {
		timeout := time.After(300 * time.Second)
		var physical observation
		for len(physical.hosts) == 0 {
			select {
			case m := <-observed:
				if len(m.hosts) > 0 && strings.HasPrefix(m.hosts[0], "bulk-") {
					physical = m
				}
			case <-timeout:
				t.Fatalf("missing coherent bulk notification %d", turn)
			}
		}
		require.True(t, physical.signed)
		for host, due := range priorDeadlines {
			require.False(t, physical.entered.Before(due), "early repeat for %s", host)
		}
		require.Len(t, physical.hosts, len(bulk))
		require.Len(t, physical.deliveries, len(bulk))
		seen := map[string]bool{}
		for n, id := range physical.deliveries {
			require.False(t, previous[id])
			previous[id] = true
			seen[physical.hosts[n]] = true
		}
		for _, m := range bulk {
			require.True(t, seen[string(m.Labels["host"])])
		}
		require.Eventually(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			for _, id := range physical.deliveries {
				if confirmed[id].IsZero() {
					return false
				}
			}
			return true
		}, 5*time.Second, 10*time.Millisecond)
		mu.Lock()
		for n, id := range physical.deliveries {
			priorDeadlines[physical.hosts[n]] = confirmed[id]
		}
		mu.Unlock()
		require.Equal(t, before, siblingTiming())
	}
	require.Positive(t, earlyCovered.Load(), "a native group interval before next eligibility must be covered")
	require.Less(t, admissions.Load(), int32(160), "4109 members use bounded private chunks per physical notification")
	// The same tracked 4109 keep their original journal guards after moving
	// to a direct-only receiver. It requires no signed callback consumer.
	large.Store(false)
	enabled.Store(false)
	renewals := uncommissionedRenewals.Load()
	releaseDirect := silenceFixtureCohort(t, instance, registry, "batch", "large")
	direct := strings.Replace(bigConfig, "http://alertmanager-middleware:9400"+alert.NativeCallbackPath, "http://direct.example/direct", 1)
	direct = direct[:strings.Index(direct, "    http_config:")]
	direct = strings.Replace(direct, "group_wait: 5s", "group_wait: 12s", 1)
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(direct), 0600))
	require.NoError(t, instance.Reload())
	require.Eventually(t, func() bool { return uncommissionedRenewals.Load() > renewals && capability(instance) }, 16*time.Second, 100*time.Millisecond)
	large.Store(true)
	started := admissions.Load()
	releaseDirect("team", bulk)
	timeout := time.After(210 * time.Second)
	for {
		select {
		case m := <-observed:
			if len(m.hosts) == 0 || !strings.HasPrefix(m.hosts[0], "bulk-") {
				continue
			}
			require.False(t, m.signed)
			require.Len(t, m.hosts, len(bulk))
			require.Empty(t, m.deliveries)
			require.Greater(t, admissions.Load(), started)
			require.Less(t, admissions.Load()-started, int32(80))
			goto directDelivered
		case <-timeout:
			t.Fatal("tracked direct group did not enter")
		}
	}
directDelivered:
	untracked := member(time.Now(), "direct-only", "new", false)
	require.NoError(t, provider.Put(t.Context(), untracked))
	next("direct-only", false)
	mu.Lock()
	_, exists := rows[untracked.Fingerprint().String()]
	mu.Unlock()
	require.False(t, exists, "untracked direct delivery must never enroll")

	// A prepared direct URL exercises both inspection and admission. Every
	// returned claimed target includes its full 4096-byte receiver name.
	large.Store(false)
	releaseLong := silenceFixtureCohort(t, instance, registry, "long_receiver", "yes")
	urlFile := write("direct-long-url", "http://direct.example/long")
	longConfig := fmt.Sprintf("route:\n  receiver: quiet\n  group_by: [batch]\n  group_wait: 12s\n  group_interval: 90s\n  repeat_interval: 1h\n  routes:\n  - receiver: %s\n    matchers: ['long_receiver=yes']\nreceivers:\n- name: quiet\n- name: %s\n  webhook_configs:\n  - url_file: %s\n    send_resolved: true\n", longName, longName, urlFile)
	require.NoError(t, os.WriteFile(opts.ConfigFile, []byte(longConfig), 0600))
	require.NoError(t, instance.Reload())
	releaseLong(longName, bulk[:64])
	deadline := time.After(150 * time.Second)
	for {
		select {
		case m := <-observed:
			if m.path != "/long" {
				continue
			}
			require.False(t, m.signed)
			require.Len(t, m.hosts, 64)
			var want []string
			for _, s := range bulk[:64] {
				want = append(want, string(s.Labels["host"]))
			}
			require.ElementsMatch(t, want, m.hosts)
			require.Eventually(t, func() bool { mu.Lock(); defer mu.Unlock(); return longSettled == 64 }, 5*time.Second, 10*time.Millisecond)
			mu.Lock()
			inspects, admits := longCommands["inspect-cohort"], longCommands["admit-cohort"]
			mu.Unlock()
			require.Greater(t, inspects, 1)
			require.Greater(t, admits, 1)
			require.Never(t, func() bool {
				select {
				case extra := <-observed:
					return extra.path == "/long"
				default:
					return false
				}
			}, 100*time.Millisecond, 10*time.Millisecond)
			return
		case <-deadline:
			t.Fatal("long receiver did not send the original 64-member group")
		}
	}
}
