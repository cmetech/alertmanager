package v2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/api/metrics"
	"github.com/prometheus/alertmanager/api/v2/models"
	alertops "github.com/prometheus/alertmanager/api/v2/restapi/operations/alert"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/provider/mem"
)

// Invoked by the isolated Python fixture owning the loopback TLS listener, AM
// ASGI application and disposable SQLite database. Never dial a deployed AM.
func TestManagedNativeJoinedOwner(t *testing.T) {
	addr := os.Getenv("OSCAR_MANAGED_FIXTURE_ADDR")
	if addr == "" {
		t.Skip("requires owned Python managed-episode fixture")
	}
	host, _, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", host)
	ca, keyfile := os.Getenv("OSCAR_MANAGED_FIXTURE_CA"), os.Getenv("OSCAR_MANAGED_FIXTURE_KEY")
	client, err := newManagedClient(ca, keyfile)
	require.NoError(t, err)
	client.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "alertmanager-middleware:9400", address)
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
	}
	provider, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer provider.Close()
	provider.EnableManaged()
	owner := &managedOwner{epoch: strings.Repeat("e", 32), store: provider, client: client, gates: map[string]*managedGate{}}
	mode := os.Getenv("OSCAR_MANAGED_FIXTURE_MODE")
	if mode != "joined" && mode != "restart-reservation" && mode != "future-start" {
		var capability struct {
			Contract string
			Worker   bool
		}
		err = client.call(t.Context(), "capability", map[string]any{}, &capability)
		require.Error(t, err, mode)
		return
	}
	go owner.maintain()
	require.Eventually(t, owner.ready.Load, 4*time.Second, 10*time.Millisecond)
	api := API{managedOwner: owner, alerts: provider, logger: promslog.NewNopLogger(), m: metrics.NewAlerts(prometheus.NewRegistry()), alertmanagerConfig: &config.Config{Global: &config.GlobalConfig{ResolveTimeout: model.Duration(time.Minute)}}}
	sourceKey := bytes.Repeat([]byte("s"), 32)
	guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch models.PostableAlerts
		require.NoError(t, json.NewDecoder(r.Body).Decode(&batch))
		api.postAlertsHandler(alertops.PostAlertsParams{HTTPRequest: r, Alerts: batch}).WriteResponse(w, runtime.TextProducer())
	}), map[string][]byte{"smtpreceiver/v1": sourceKey})
	var vectors struct{ Valid map[string]any }
	raw, err := os.ReadFile("testdata/managed_operation_v1.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &vectors))
	event := func(id, kind string, gen int) map[string]any {
		out := map[string]any{}
		for k, v := range vectors.Valid {
			out[k] = v
		}
		out["issued_at"] = time.Now().Unix()
		out["deadline"] = time.Now().Unix() + 10
		out["expected_generation"] = gen
		out["kind"] = kind
		out["event_id"] = id
		out["source_digest"] = hex.EncodeToString(sha256.New().Sum(nil))
		digest := sha256.Sum256([]byte(id))
		out["source_digest"] = hex.EncodeToString(digest[:])
		out["attempt"] = hex.EncodeToString(digest[:16])
		if kind != "clear" {
			out["clear_at"] = ""
		} else {
			out["clear_at"] = out["started_at"]
		}
		return out
	}
	post := func(op map[string]any, path string, severity string) (*httptest.ResponseRecorder, model.Fingerprint) {
		encoded, e := json.Marshal(op)
		require.NoError(t, e)
		kind := "problem"
		resolved := "false"
		start := op["started_at"].(string)
		if op["kind"] == "clear" {
			kind, resolved, start = "resolution", "true", op["clear_at"].(string)
		}
		labels := models.LabelSet{"alertname": "fixture", "node": "node", "correlation_key": op["correlation"].(string), "alert_type": kind, "is_resolution": resolved, "severity": severity}
		at, e := time.Parse(time.RFC3339Nano, start)
		require.NoError(t, e)
		body, e := json.Marshal([]map[string]any{{"labels": labels, "annotations": models.LabelSet{managedAnnotation: string(encoded)}, "startsAt": strfmt.DateTime(at)}})
		require.NoError(t, e)
		r := conversionRequest(body, "smtpreceiver", sourceKey)
		r.URL.Path = path
		sum := sha256.Sum256(body)
		mac := hmac.New(sha256.New, sourceKey)
		mac.Write([]byte(strings.Join([]string{"native-conversion-ingress-v1", "POST", path, "smtpreceiver", "v1", r.Header.Get("X-Oscar-Conversion-Time"), hex.EncodeToString(sum[:])}, "\n")))
		r.Header.Set("X-Oscar-Conversion-Signature", hex.EncodeToString(mac.Sum(nil)))
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		return w, APILabelSetToModelLabelSet(labels).Fingerprint()
	}
	u1 := event("11111111-1111-4111-8111-111111111111", "raise", 0)
	if mode == "future-start" {
		api.alertmanagerConfig.Global.ResolveTimeout = model.Duration(150 * time.Millisecond)
		start := time.Now().UTC().Add(1200 * time.Millisecond).Truncate(time.Millisecond)
		u1["started_at"] = start.Format(time.RFC3339Nano)
		for _, path := range []string{"/api/v2/alerts", managedReadPath, managedConfirmPath} {
			response, fp := post(u1, path, "major")
			assert.Equal(t, http.StatusServiceUnavailable, response.Code, "%s: %s", path, response.Body.String())
			_, missing := provider.Get(fp)
			require.Error(t, missing)
		}
		encoded, e := json.Marshal(u1)
		require.NoError(t, e)
		key, e := boundKey(encoded)
		require.NoError(t, e)
		_, hasStamp := provider.ManagedApplied(key)
		require.False(t, hasStamp)
		miss, e := owner.state(t.Context(), "lookup", map[string]any{"operation": json.RawMessage(encoded)}, key)
		require.NoError(t, e)
		require.Equal(t, "complete_miss", miss.State)
		require.Zero(t, miss.Generation)
		time.Sleep(time.Until(start))
		u1["attempt"] = strings.Repeat("f", 32)
		u1["issued_at"] = time.Now().Unix()
		u1["deadline"] = time.Now().Unix() + 10
		response, _ := post(u1, managedReadPath, "major")
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		response, fp := post(u1, "/api/v2/alerts", "major")
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		require.Contains(t, response.Body.String(), "forwarded")
		stored, e := provider.Get(fp)
		require.NoError(t, e)
		require.True(t, start.Equal(stored.StartsAt))
		return
	}
	w, _ := post(u1, managedReadPath, "major")
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "complete_miss")
	ch := make(chan int, 2)
	for range 2 {
		go func() { response, _ := post(u1, "/api/v2/alerts", "major"); ch <- response.Code }()
	}
	require.Equal(t, 200, <-ch)
	require.Equal(t, 200, <-ch)
	w, old := post(u1, "/api/v2/alerts", "major")
	require.Equal(t, 200, w.Code, w.Body.String())
	if mode == "restart-reservation" {
		firstRaw, _ := json.Marshal(u1)
		key, e := boundKey(firstRaw)
		require.NoError(t, e)
		var settled ownerState
		require.Eventually(t, func() bool {
			settled, e = owner.state(t.Context(), "lookup", map[string]any{"operation": json.RawMessage(firstRaw)}, key)
			return e == nil && settled.Phase == "settled"
		}, 4*time.Second, 20*time.Millisecond)
		// Crash immediately after the actual reserve, before SQL promotion.
		proposal := event("22222222-2222-4222-8222-222222222222", "update", 1)
		proposal["deadline"] = time.Now().Unix() + 2
		original, _ := json.Marshal(proposal)
		proposed := settled.Current.Projection
		proposed.Alert.Labels = proposed.Alert.Labels.Clone()
		proposed.Alert.Labels["severity"] = "minor"
		proposed.Fingerprint = proposed.Alert.Fingerprint().String()
		locked, e := owner.state(t.Context(), "reserve", map[string]any{"operation": json.RawMessage(original), "generation": 1, "native_epoch": owner.epoch, "projection": proposed}, key)
		require.NoError(t, e)
		require.Equal(t, "reserved", locked.Phase)
		provider.Close()
		replacementStore, e := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
		require.NoError(t, e)
		defer replacementStore.Close()
		replacementStore.EnableManaged()
		replacement := &managedOwner{epoch: strings.Repeat("f", 32), store: replacementStore, client: client, gates: map[string]*managedGate{}}
		go replacement.maintain()
		require.Eventually(t, replacement.ready.Load, 4*time.Second, 20*time.Millisecond)
		restored, e := replacementStore.Get(old)
		require.NoError(t, e)
		require.Equal(t, model.LabelValue("major"), restored.Labels["severity"])
		var after ownerState
		require.Eventually(t, func() bool {
			after, e = replacement.state(t.Context(), "lookup", map[string]any{"operation": json.RawMessage(firstRaw)}, key)
			return e == nil && after.Phase == "cancelled" && after.Generation == 3
		}, 12*time.Second, 30*time.Millisecond)
		require.Equal(t, settled.Current.Execution, after.Current.Execution)
		_, e = owner.state(t.Context(), "applied", slotCommand(locked.Pending, 2), key)
		require.Error(t, e)
		_, e = owner.submit(t.Context(), key, locked.Pending, 2)
		require.Error(t, e)
		api.managedOwner = replacement
		api.alerts = replacementStore
		retry := event(proposal["event_id"].(string), "update", 3)
		retry["attempt"] = strings.Repeat("9", 32)
		accepted, _ := post(retry, "/api/v2/alerts", "minor")
		require.Equal(t, 200, accepted.Code, accepted.Body.String())
		require.Contains(t, accepted.Body.String(), "forwarded")
		return
	}
	u2 := event("22222222-2222-4222-8222-222222222222", "update", 1)
	w, newfp := post(u2, "/api/v2/alerts", "minor")
	require.Equal(t, 200, w.Code, w.Body.String())
	oldAlert, e := provider.Get(old)
	require.NoError(t, e)
	require.True(t, oldAlert.Resolved())
	cl := event("33333333-3333-4333-8333-333333333333", "clear", 2)
	w, clearfp := post(cl, "/api/v2/alerts", "cleared")
	require.Equal(t, 200, w.Code, w.Body.String())
	newAlert, e := provider.Get(newfp)
	require.NoError(t, e)
	require.True(t, newAlert.Resolved())
	clear, e := provider.Get(clearfp)
	require.NoError(t, e)
	require.False(t, clear.Resolved())
	w, _ = post(u1, "/api/v2/alerts", "major")
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "episode_closed")
	w, _ = post(u1, managedConfirmPath, "major")
	require.Equal(t, 503, w.Code, "old negative confirmation")
	another := event("44444444-4444-4444-8444-444444444444", "raise", 0)
	another["episode_id"] = "55555555-5555-4555-8555-555555555555"
	another["correlation"] = "lab:node:" + another["episode_id"].(string)
	api.alertmanagerConfig.Global.ResolveTimeout = model.Duration(3 * time.Second)
	w, fp := post(another, "/api/v2/alerts", "major")
	require.Equal(t, 200, w.Code, w.Body.String())
	require.NotEqual(t, old, fp)
	beforeRenew, err := provider.Get(fp)
	require.NoError(t, err)
	originalEnd := beforeRenew.EndsAt
	time.Sleep(time.Until(originalEnd.Add(-1500 * time.Millisecond)))
	refreshed, _ := post(another, "/api/v2/alerts", "major")
	require.Equal(t, 200, refreshed.Code, refreshed.Body.String())
	afterRenew, err := provider.Get(fp)
	require.NoError(t, err)
	require.Greater(t, afterRenew.EndsAt.Sub(originalEnd), time.Second)
	time.Sleep(time.Until(originalEnd.Add(80 * time.Millisecond)))
	provider.Close()
	restarted, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer restarted.Close()
	restarted.EnableManaged()
	replacement := &managedOwner{epoch: strings.Repeat("f", 32), store: restarted, client: client, gates: map[string]*managedGate{}}
	go replacement.maintain()
	require.Eventually(t, replacement.ready.Load, 4*time.Second, 10*time.Millisecond)
	open, err := restarted.Get(fp)
	require.NoError(t, err)
	require.True(t, open.ManagedReceiver)
	require.Equal(t, afterRenew.EndsAt.UnixMilli(), open.EndsAt.UnixMilli(), "restart must restore acknowledged renewal")
	require.False(t, open.Resolved())
	restored, err := restarted.Get(clearfp)
	require.NoError(t, err)
	require.Equal(t, clear.StartsAt, restored.StartsAt)
	require.Equal(t, clear.EndsAt.UnixMilli(), restored.EndsAt.UnixMilli())
	_, err = restarted.Get(old)
	require.Error(t, err)
}

type ownerTransport func(*http.Request) (*http.Response, error)

func (f ownerTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManagedRestartEvidenceAndCloseCompensation(t *testing.T) {
	raw, err := os.ReadFile("testdata/managed_operation_v1.json")
	require.NoError(t, err)
	var vector struct{ Valid map[string]any }
	require.NoError(t, json.Unmarshal(raw, &vector))
	op := vector.Valid
	op["deadline"] = time.Now().Unix() - 30
	signed, _ := json.Marshal(op)
	key, err := boundKey(signed)
	require.NoError(t, err)
	p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	p.EnableManaged()
	now := time.Now()
	incoming := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "episode", "alert_type": "problem"}, StartsAt: now.Add(-time.Hour), EndsAt: now.Add(time.Hour)}, now, false)
	slot := &ownerSlot{Operation: signed, Epoch: strings.Repeat("a", 32), Projection: snapshot(incoming), Execution: "11111111-1111-4111-8111-111111111111", Generation: 1}
	row := ownerState{State: "reserved", Phase: "reserved", Key: key, Identity: signed, Generation: 1, Pending: slot}
	var calls []string
	transport := ownerTransport(func(r *http.Request) (*http.Response, error) {
		action := strings.TrimPrefix(r.URL.String(), managedAuthority)
		calls = append(calls, action)
		response, _ := json.Marshal(row)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: make(http.Header)}, nil
	})
	owner := &managedOwner{epoch: strings.Repeat("b", 32), store: p, client: &managedClient{http: &http.Client{Transport: transport}}}
	// Prior to full restore the replacement cannot supersede an unpromoted operation.
	require.Error(t, owner.recover(t.Context(), key, &managedGate{}, row))
	require.Empty(t, calls)
	owner.restored.Store(true)
	require.NoError(t, owner.recover(t.Context(), key, &managedGate{}, row))
	require.Equal(t, []string{"cancel-unpromoted"}, calls)
	calls = nil
	owner.epoch = slot.Epoch
	require.NoError(t, owner.recover(t.Context(), key, &managedGate{}, row))
	require.Equal(t, []string{"cancel-unapplied"}, calls)
	// SQL missed the provider's promotion. A new owner claims only its exact stamp.
	require.NoError(t, p.ApplyManaged(t.Context(), key, incoming, slot.stamp(), func() error { return nil }))
	owner.epoch = strings.Repeat("b", 32)
	require.NoError(t, owner.recover(t.Context(), key, &managedGate{}, row))
	require.Equal(t, []string{"cancel-unapplied", "applied"}, calls)
	// A close won between the native mutation and its SQL response.
	closed := time.Now().UnixMilli()
	row.Generation, row.State, row.Phase, row.Closed = 2, "exact_closed", "closing", &closed
	state, err := owner.recheckClosed(t.Context(), key, signed, &managedGate{}, context.DeadlineExceeded)
	require.NoError(t, err)
	require.Equal(t, "episode_closed", state)
	retained, err := p.Get(incoming.Fingerprint())
	require.NoError(t, err)
	require.True(t, retained.Resolved())
	require.Equal(t, []string{"cancel-unapplied", "applied", "lookup", "retired"}, calls)
	row.Identity = json.RawMessage("{}")
	_, err = owner.state(t.Context(), "lookup", map[string]string{"key": key}, key)
	require.Error(t, err)
}

func TestManagedMaintenanceBlockedRetirementAllowsSiblingRecovery(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run(map[bool]string{true: "startup", false: "periodic"}[startup], func(t *testing.T) {
			t.Parallel()
			checkBlockedMaintenance(t, startup)
		})
	}
}

func checkBlockedMaintenance(t *testing.T, startup bool) {
	p, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, promslog.NewNopLogger(), eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	defer p.Close()
	p.EnableManaged()
	fixture, err := os.ReadFile("testdata/managed_operation_v1.json")
	require.NoError(t, err)
	var v struct{ Valid map[string]any }
	require.NoError(t, json.Unmarshal(fixture, &v))
	v.Valid["kind"] = "raise"
	v.Valid["clear_at"] = ""
	var rows []ownerState
	for i, name := range []string{"first", "second"} {
		v.Valid["owner"] = name
		raw, _ := json.Marshal(v.Valid)
		key, e := boundKey(raw)
		require.NoError(t, e)
		now := time.Now()
		a := alert.New(model.Alert{Labels: model.LabelSet{"alertname": model.LabelValue(name), "alert_type": "problem"}, StartsAt: now.Add(-time.Minute), EndsAt: now.Add(time.Hour)}, now, true)
		slot := &ownerSlot{Operation: raw, Projection: snapshot(a), Generation: 1, Execution: fmt.Sprintf("%08d-1111-4111-8111-111111111111", i)}
		require.NoError(t, p.ApplyManaged(t.Context(), key, a, slot.stamp(), func() error { return nil }))
		rows = append(rows, ownerState{State: "open", Phase: "ack", Key: key, Identity: raw, Generation: 1, Pending: slot, Current: slot})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	closed := time.Now().UnixMilli()
	rows[0].Closed, rows[0].Phase, rows[0].State, rows[0].Generation = &closed, "closing", "exact_closed", 2
	_, slow := p.SlurpAndSubscribe("blocked")
	closeSlow := sync.OnceFunc(slow.Close)
	defer closeSlow()
	ordinary := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "ordinary"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Hour)}, time.Now(), false)
	for range 200 {
		require.NoError(t, p.Put(t.Context(), ordinary))
	}
	blocked := make(chan error, 1)
	go func() { blocked <- p.Put(t.Context(), ordinary) }()
	select {
	case <-blocked:
		t.Fatal("stalled subscriber did not backpressure")
	case <-time.After(25 * time.Millisecond):
	}
	var caps, redrives, retired atomic.Int32
	transport := ownerTransport(func(r *http.Request) (*http.Response, error) {
		action := strings.TrimPrefix(r.URL.Path, "/api/v1/internal/managed-receiver/")
		var cmd map[string]any
		if e := json.NewDecoder(r.Body).Decode(&cmd); e != nil {
			return nil, e
		}
		var reply any
		switch action {
		case "capability":
			caps.Add(1)
			reply = map[string]any{"contract": managedContract, "worker": true, "capacity": maxManagedRows, "rows": 2}
		case "scan":
			keys := []string{rows[0].Key, rows[1].Key}
			if !startup && cmd["restore"] == true {
				keys = []string{}
			}
			reply = map[string]any{"keys": keys}
		case "lookup":
			if cmd["key"] == rows[0].Key {
				reply = rows[0]
			} else {
				reply = rows[1]
			}
		case "retired":
			retired.Add(1)
			reply = rows[0]
		case "recover":
			rc := rows[1]
			rc.Redrive = true
			reply = rc
		case "submit":
			redrives.Add(1)
			reply = map[string]string{"status": "broker_ack", "execution_id": rows[1].Pending.Execution, "digest": rows[1].Pending.claims().Digest}
		case "ack":
			reply = rows[1]
		default:
			return nil, fmt.Errorf("unexpected maintenance action %s", action)
		}
		body, e := json.Marshal(reply)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, e
	})
	owner := &managedOwner{epoch: strings.Repeat("f", 32), store: p, client: &managedClient{http: &http.Client{Transport: transport}}, gates: map[string]*managedGate{}}
	go owner.maintain()
	require.Eventually(t, func() bool { return caps.Load() >= 2 && redrives.Load() > 0 }, 8*time.Second, 25*time.Millisecond, "A must not block capability polling or B's acknowledged-but-missing worker recovery")
	require.Zero(t, retired.Load())
	require.Equal(t, !startup, owner.ready.Load(), "startup requires complete restoration while an existing healthy runtime can progress")
	require.Eventually(t, func() bool {
		_, release, e := owner.enter(rows[0].Key)
		if e != nil {
			return false
		}
		release()
		return true
	}, 5*time.Second, 10*time.Millisecond, "a blocked retirement must release its episode gate")
	closeSlow()
	require.NoError(t, <-blocked)
	require.Eventually(t, func() bool { return retired.Load() > 0 && owner.ready.Load() }, 8*time.Second, 25*time.Millisecond)
}
