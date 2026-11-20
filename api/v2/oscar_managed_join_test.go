package v2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
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
	if mode != "joined" {
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
		body, e := json.Marshal(models.PostableAlerts{&models.PostableAlert{Alert: models.Alert{Labels: labels}, Annotations: models.LabelSet{managedAnnotation: string(encoded)}, StartsAt: strfmt.DateTime(at)}})
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
	w, fp := post(another, "/api/v2/alerts", "major")
	require.Equal(t, 200, w.Code, w.Body.String())
	require.NotEqual(t, old, fp)
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
	// A replacement process cannot infer that a previous epoch never applied.
	require.Error(t, owner.recover(t.Context(), key, &managedGate{}, row))
	require.Empty(t, calls)
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
