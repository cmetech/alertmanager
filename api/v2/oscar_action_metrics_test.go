// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
)

func writeKey(t *testing.T, fill string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat(fill, 32)), 0o600))
	return path
}

// fakeJournal is a minimal OSCAR native action endpoint. Admissions block
// until released; lease commands answer immediately with a valid lease.
type fakeJournal struct {
	server   *httptest.Server
	entered  chan struct{}
	release  chan struct{}
	mu       sync.Mutex
	leaseRem []string // remote addresses that served lease commands
	admitRem []string // remote addresses that served admissions
}

func newFakeJournal(t *testing.T) *fakeJournal {
	t.Helper()
	f := &fakeJournal{entered: make(chan struct{}, 64), release: make(chan struct{})}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		cmd := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		switch cmd {
		case "acquire-authority", "renew-authority":
			f.mu.Lock()
			f.leaseRem = append(f.leaseRem, r.RemoteAddr)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"recipient_binding": recipientBinding, "recipient_key": strings.Repeat("a", 64), "protocol": "native-action-store-v1",
				"recovery_selectors": 1, "terminal_observations": 2, "authority_id": body["authority_id"], "owner_id": body["owner_id"],
				"epoch": 7, "renew_seconds": 10, "expires_at": time.Now().Add(30 * time.Second),
			})
		default:
			f.mu.Lock()
			f.admitRem = append(f.admitRem, r.RemoteAddr)
			f.mu.Unlock()
			f.entered <- struct{}{}
			select {
			case <-f.release:
			case <-r.Context().Done():
			}
			_, _ = w.Write([]byte("[]"))
		}
	}))
	t.Cleanup(f.server.Close)
	t.Cleanup(func() {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	})
	return f
}

func (f *fakeJournal) dial(ctx context.Context, network, _ string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, f.server.Listener.Addr().String())
}

// AC-1: renewal succeeds while every delivery connection is held by admissions.
func TestActionLeaseRenewsWhileDeliverySaturated(t *testing.T) {
	f := newFakeJournal(t)
	c, err := newActionClient(ActionOwnerConfig{Scheme: "http", StoreKeyFile: writeKey(t, "k"), MaxConns: 2}, f.dial, nil)
	require.NoError(t, err)
	o := newNativeActionOwner(defaultActionAuthority, c, testActionDispatch{})
	for range 3 { // two occupy the pool, a third waits for a delivery connection
		go func() { _ = c.call(context.Background(), "admit-cohort", map[string]any{}, &[]cohortResult{}) }()
	}
	for range 2 {
		select {
		case <-f.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("admissions did not saturate the delivery pool")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, o.leaseTick(ctx))
	require.True(t, o.lease.ExpiresAt.After(time.Now()))
	f.mu.Lock()
	defer f.mu.Unlock()
	require.Len(t, f.leaseRem, 2) // acquire + renew
	for _, lease := range f.leaseRem {
		require.NotContains(t, f.admitRem, lease)
	}
}

// AC-2: pool size and timeout are configurable with documented defaults; the lease client is fixed.
func TestActionOwnerPoolConfig(t *testing.T) {
	key := writeKey(t, "k")
	for _, tc := range []struct {
		conf            ActionOwnerConfig
		conns           int
		timeout, header time.Duration
	}{
		{ActionOwnerConfig{Scheme: "http", StoreKeyFile: key}, 16, 3 * time.Second, 2 * time.Second},
		{ActionOwnerConfig{Scheme: "http", StoreKeyFile: key, MaxConns: 8, Timeout: 900 * time.Millisecond}, 8, 900 * time.Millisecond, 600 * time.Millisecond},
		{ActionOwnerConfig{Scheme: "http", StoreKeyFile: key, MaxConns: 4, Timeout: 6 * time.Second}, 4, 6 * time.Second, 4 * time.Second},
	} {
		c, err := newActionClient(tc.conf, nil, nil)
		require.NoError(t, err)
		delivery := c.http.Transport.(*http.Transport)
		require.Equal(t, tc.conns, delivery.MaxConnsPerHost)
		require.Equal(t, tc.conns, delivery.MaxIdleConnsPerHost)
		require.Equal(t, tc.header, delivery.ResponseHeaderTimeout)
		require.Equal(t, tc.timeout, c.http.Timeout)
		lease := c.lease.Transport.(*http.Transport)
		require.NotSame(t, delivery, lease)
		require.Equal(t, 2, lease.MaxConnsPerHost)
		require.Equal(t, 3*time.Second, c.lease.Timeout)
		require.Equal(t, 2*time.Second, lease.ResponseHeaderTimeout)
		require.NotNil(t, c.lease.CheckRedirect)
	}
	_, err := newActionClient(ActionOwnerConfig{Scheme: "http", StoreKeyFile: key, MaxConns: -1}, nil, nil)
	require.Error(t, err)
}

// AC-3: the native path registers its capacity metrics and counts calls, holds and overflow.
func TestActionMetricsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), reg)
	require.NoError(t, err)
	f := newFakeJournal(t)
	require.NoError(t, api.InstallActionOwner(ActionOwnerConfig{
		Enabled: true, Scheme: "http",
		StoreKeyFile: writeKey(t, "s"), OperatorKeyFile: writeKey(t, "o"), PolicyKeyFile: writeKey(t, "p"),
	}, f.dial))
	o := api.actionOwner
	require.NoError(t, o.leaseTick(t.Context()))
	o.CountHeld(reconcile, true)
	o.CountHeld(context.DeadlineExceeded, false)
	o.CountHeld(errors.Join(unavailable, reconcile), false) // first protocol code
	o.CountHeld(errors.New("free text"), false)
	o.mu.Lock()
	o.recovered = true
	for i := range o.membership {
		o.membership[i] = ^uint64(0)
	}
	start := time.Now()
	for n := range maxTransitions + 1 { // distinct variants of one key overflow its transition bound
		s := alert.New(model.Alert{Labels: model.LabelSet{"alertname": "x"}, StartsAt: start.Add(time.Duration(n) * time.Second)}, start, false)
		o.bufferLocked("n/overflow", nil, s, true)
	}
	o.maxHandoffs = len(o.handoffs) // hand-offs at their bound: enrollment is refused
	o.mu.Unlock()
	_, err = o.obtainSlot(t.Context(), "n/new", func() (*episodeSlot, error) { return nil, nil })
	require.ErrorIs(t, err, unavailable)

	families, err := reg.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, mf := range families {
		names[mf.GetName()] = true
	}
	for _, name := range []string{
		"alertmanager_oscar_native_calls_total", "alertmanager_oscar_native_call_duration_seconds",
		"alertmanager_oscar_native_pool_wait_seconds", "alertmanager_oscar_native_held_total",
		"alertmanager_oscar_native_resident_slots", "alertmanager_oscar_native_handoff_overflow_total",
		"alertmanager_oscar_native_lease_ready", "alertmanager_oscar_native_handoff_backpressure_total",
	} {
		require.True(t, names[name], name)
	}
	m := o.metrics
	require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("renew-authority", "ok")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("acquire-authority", "ok")), 0)
	var wait dto.Metric
	require.NoError(t, m.poolWait.WithLabelValues("lease").(prometheus.Histogram).Write(&wait))
	require.EqualValues(t, 2, wait.GetHistogram().GetSampleCount())
	require.InDelta(t, 1, testutil.ToFloat64(m.held.WithLabelValues("ACTION_RECONCILIATION_REQUIRED", "resolved")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.held.WithLabelValues("TIMEOUT", "firing")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.held.WithLabelValues("NATIVE_UNAVAILABLE", "firing")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.held.WithLabelValues("OTHER", "firing")), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.overflow), 0)
	require.InDelta(t, 1, testutil.ToFloat64(m.pressure), 0)
}

func TestActionCallOutcomes(t *testing.T) {
	m := newActionMetrics(prometheus.NewRegistry())
	for _, tc := range []struct {
		status  int
		body    string
		outcome string
	}{
		{200, `[]`, "ok"},
		{409, `{"detail":"ACTION_REQUEST_CONFLICT"}`, "conflict"},
		{503, ``, "unavailable"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		}
		c, err := newActionClient(ActionOwnerConfig{Scheme: "http", StoreKeyFile: writeKey(t, "k")}, dial, m)
		require.NoError(t, err)
		_ = c.call(t.Context(), "lookup-cohort", map[string]any{}, &[]cohortResult{})
		require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("lookup-cohort", tc.outcome)), 0, tc.outcome)
		srv.Close()
	}
	c, err := newActionClient(ActionOwnerConfig{Scheme: "http", StoreKeyFile: writeKey(t, "k")}, nil, m)
	require.NoError(t, err)
	require.Error(t, c.call(t.Context(), "admit-cohort", map[string]any{"x": strings.Repeat("y", actionBodyLimit)}, nil))
	require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("admit-cohort", "rejected")), 0)

	// Headers arrive, then the body stalls past the call timeout; and an incompatible lease reply.
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/renew-authority") {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer stall.Close()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, stall.Listener.Addr().String())
	}
	c, err = newActionClient(ActionOwnerConfig{Scheme: "http", StoreKeyFile: writeKey(t, "k"), Timeout: 300 * time.Millisecond}, dial, m)
	require.NoError(t, err)
	require.ErrorIs(t, c.call(t.Context(), "settle-cohort", map[string]any{}, &[]string{}), unavailable)
	require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("settle-cohort", "timeout")), 0)
	require.ErrorIs(t, c.call(t.Context(), "renew-authority", map[string]any{}, &actionLease{}), incompatibleLease)
	require.InDelta(t, 1, testutil.ToFloat64(m.calls.WithLabelValues("renew-authority", "incompatible")), 0)
	var wait dto.Metric
	require.NoError(t, m.poolWait.WithLabelValues("delivery").(prometheus.Histogram).Write(&wait))
	require.Positive(t, wait.GetHistogram().GetSampleCount())
	require.Equal(t, "CANCELED", heldReason(context.Canceled))
	require.Equal(t, "ACTION_REQUEST_CONFLICT", heldReason(fmt.Errorf("wrapped: %w", conflict)))
}
