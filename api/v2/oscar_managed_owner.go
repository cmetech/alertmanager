package v2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/dispatch"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/provider"
	"github.com/prometheus/alertmanager/store"
	"github.com/prometheus/common/model"
)

const managedAuthority = "alertmanager-middleware:9400/api/v1/internal/managed-receiver/"
const managedContract = "managed-episode-owner-v1"
const maxManagedRows = 4096

type managedClient struct {
	scheme string
	caFile string
	http   *http.Client
	token  string
}

func newManagedClient(scheme, caFile, keyFile string) (*managedClient, error) {
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("invalid managed owner scheme")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if scheme == "https" {
		ca, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("invalid managed CA")
		}
		tlsConfig.RootCAs = pool
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key = bytes.TrimSpace(key)
	if len(key) < 32 || len(key) > 256 {
		return nil, errors.New("invalid managed credential")
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig,
		MaxConnsPerHost: 16, MaxIdleConnsPerHost: 8, TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxResponseHeaderBytes: 8192, DisableCompression: true}
	return &managedClient{scheme: scheme, caFile: caFile, token: string(key), http: &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *managedClient) call(ctx context.Context, action string, body any, result any) error {
	switch action {
	case "capability", "scan", "lookup", "reserve", "applied", "renew", "submit", "ack", "recover", "retired", "compact", "cancel-unapplied", "cancel-unpromoted":
	default:
		return errors.New("invalid managed action")
	}
	data, err := json.Marshal(body)
	if err != nil || len(data) > 128<<10 {
		return errors.New("invalid managed command")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.scheme+"://"+managedAuthority+action, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (160<<10)+1))
	if err != nil || len(raw) > 160<<10 || resp.StatusCode != 200 {
		return fmt.Errorf("managed %s unavailable (HTTP %d)", action, resp.StatusCode)
	}
	return json.Unmarshal(raw, result)
}

type managedClaims struct {
	Producer string `json:"producer"`
	EventID  string `json:"event_id"`
	Digest   string `json:"source_digest"`
	Kind     string `json:"kind"`
	Attempt  string `json:"attempt"`
	Deadline int64  `json:"deadline"`
	Expected int64  `json:"expected_generation"`
}

type projection struct {
	Alert          model.Alert         `json:"alert"`
	Fingerprint    string              `json:"fingerprint"`
	Timeout        bool                `json:"timeout"`
	ResolveTimeout time.Duration       `json:"resolve_timeout"`
	Source         alert.EndTimeSource `json:"end_time_source"`
}

func snapshot(a *alert.Alert) projection {
	return projection{a.Alert, a.Fingerprint().String(), a.Timeout, a.ResolveTimeout, a.EndTimeSource}
}

func (p projection) restore() (*alert.Alert, error) {
	a := alert.New(p.Alert, time.Now(), p.Timeout)
	if err := alert.Validate(&a.Alert); err != nil || a.Fingerprint().String() != p.Fingerprint {
		return nil, errors.New("invalid frozen native projection")
	}
	a.ResolveTimeout, a.EndTimeSource = p.ResolveTimeout, p.Source
	return a, nil
}

type ownerSlot struct {
	Epoch      string          `json:"native_epoch"`
	Operation  json.RawMessage `json:"operation"`
	Projection projection      `json:"projection"`
	Execution  string          `json:"execution_id"`
	Generation int64           `json:"generation"`
}

func (s *ownerSlot) claims() (o managedClaims) {
	if s != nil {
		_ = json.Unmarshal(s.Operation, &o)
	}
	return
}

func (s *ownerSlot) stamp() provider.ManagedStamp {
	op := s.claims()
	return provider.ManagedStamp{Generation: s.Generation, Attempt: op.Attempt, Digest: op.Digest}
}

type ownerState struct {
	Identity   json.RawMessage `json:"identity"`
	State      string          `json:"state"`
	Key        string          `json:"key"`
	Generation int64           `json:"generation"`
	Phase      string          `json:"phase"`
	Current    *ownerSlot      `json:"current"`
	Pending    *ownerSlot      `json:"pending"`
	Closed     *int64          `json:"closed_ms"`
	Redrive    bool            `json:"redrive"`
	Replay     bool            `json:"replay"`
}

type managedStore interface {
	Get(model.Fingerprint) (*alert.Alert, error)
	EnableManaged()
	ManagedShutdown() <-chan struct{}
	ApplyManaged(context.Context, string, *alert.Alert, provider.ManagedStamp, func() error) error
	ManagedApplied(string) (provider.ManagedStamp, bool)
	ReleaseManaged(string, int64)
}

type managedGate struct {
	durable           bool
	inflight          bool
	appliedGeneration int64
	appliedAttempt    string
	provenUnapplied   string
}
type managedOwner struct {
	eligible func(context.Context, *alert.Alert, string, string) (bool, error)
	epoch    string
	client   *managedClient
	store    managedStore
	ready    atomic.Bool
	restored atomic.Bool
	mu       sync.Mutex
	gates    map[string]*managedGate
}

func (api *API) InstallManagedOwner(scheme, ca, key string, forbidden map[string][]byte, callback []byte) error {
	if ca == "" && key == "" {
		return nil
	}
	client, err := newManagedClient(scheme, ca, key)
	if err != nil {
		return err
	}
	if client.token == string(callback) || len(callback) < 32 {
		return errors.New("managed owner requires independent callback")
	}
	for _, other := range forbidden {
		if client.token == string(other) {
			return errors.New("managed owner credential reused")
		}
	}
	store, ok := api.alerts.(managedStore)
	if !ok {
		return errors.New("managed provider missing")
	}
	store.EnableManaged()
	var random [16]byte
	_, _ = rand.Read(random[:])
	o := &managedOwner{epoch: hex.EncodeToString(random[:]), store: store, client: client, gates: make(map[string]*managedGate)}
	o.eligible = api.managedMemberEligible
	api.managedOwner = o
	go o.maintain()
	return nil
}

// Re-evaluate membership on each actual webhook attempt, including native retries after History wait.
func (api *API) managedMemberEligible(ctx context.Context, incoming *alert.Alert, receiver, group string) (bool, error) {
	current, err := api.alerts.Get(incoming.Fingerprint())
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !current.ManagedReceiver || current.ManagedMember != incoming.ManagedMember || !current.StartsAt.Equal(incoming.StartsAt) {
		return false, nil
	}
	now := time.Now()
	if current.ResolvedAt(now) != incoming.ResolvedAt(now) {
		return false, nil
	}
	api.mtx.RLock()
	root, setStatus, timing := api.route, api.setAlertStatus, api.timing
	api.mtx.RUnlock()
	if root == nil || setStatus == nil || !api.conversionCallbackReady() {
		return false, errors.New("managed notification eligibility unavailable")
	}
	state := predictAlertStatus(ctx, setStatus, current)
	if len(state.SilencedBy) != 0 || len(state.InhibitedBy) != 0 || state.State == alert.AlertStateSuppressed {
		return false, nil
	}
	for _, route := range root.Match(current.Labels) {
		opts := route.RouteOpts
		if opts.Receiver != receiver || dispatch.GroupKeyForAlert(current, route) != group {
			continue
		}
		if len(opts.ActiveTimeIntervals)+len(opts.MuteTimeIntervals) != 0 {
			if timing == nil || timing.Muter == nil {
				return false, errors.New("managed route timing unavailable")
			}
			inactive, muted, err := notify.MutedByTimeIntervals(timing.Muter, opts.ActiveTimeIntervals, opts.MuteTimeIntervals, now)
			if err != nil {
				return false, err
			}
			if len(inactive)+len(muted) != 0 {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

func (o *managedOwner) attachMember(a *alert.Alert, key string, slot *ownerSlot) {
	op := slot.claims()
	a.ManagedOperationKind = op.Kind
	a.ManagedMember = alert.ManagedMembership{Episode: key, Generation: slot.Generation, Event: op.EventID, Digest: op.Digest}
	a.ManagedEligible = o.eligible
}

func (o *managedOwner) enter(key string) (*managedGate, func(), error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	g := o.gates[key]
	if g == nil {
		if len(o.gates) >= maxManagedRows {
			return nil, nil, errors.New("managed episode capacity")
		}
		g = &managedGate{}
		o.gates[key] = g
	}
	if g.inflight {
		return nil, nil, errors.New("managed episode busy")
	}
	g.inflight = true
	return g, func() {
		o.mu.Lock()
		g.inflight = false
		if !g.durable {
			delete(o.gates, key)
		}
		o.mu.Unlock()
	}, nil
}

func boundKey(raw json.RawMessage) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	bound := map[string]string{}
	for _, name := range []string{"producer", "owner", "locator", "source_id", "tid", "handler", "revision", "binding_digest", "episode_id", "correlation", "started_at"} {
		var value string
		if err := json.Unmarshal(fields[name], &value); err != nil {
			return "", err
		}
		if name == "started_at" {
			start, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || start.Nanosecond()%1e6 != 0 {
				return "", errors.New("invalid managed start")
			}
			value = start.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		bound[name] = value
	}
	data, _ := json.Marshal(bound)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (o *managedOwner) state(ctx context.Context, action string, body any, key string) (ownerState, error) {
	var state ownerState
	err := o.client.call(ctx, action, body, &state)
	if err == nil {
		switch state.State {
		case "complete_miss":
			initial := state.Generation == 0 && state.Key == "" && state.Identity == nil && state.Phase == "" && action == "lookup"
			bound, idErr := boundKey(state.Identity)
			cancelled := state.Generation > 0 && state.Key == key && idErr == nil && bound == key && state.Phase == "cancelled"
			if (!initial && !cancelled) || state.Pending != nil || state.Current != nil || state.Closed != nil {
				err = errors.New("invalid negative evidence")
			}
		case "reserved", "open", "exact_closed":
			id, e := boundKey(state.Identity)
			if e != nil || id != key || state.Generation < 1 || state.Key != key || (state.State == "exact_closed") != (state.Closed != nil) {
				err = errors.New("invalid owned evidence")
			}
			for _, slot := range []*ownerSlot{state.Current, state.Pending} {
				if slot == nil {
					continue
				}
				slotKey, e := boundKey(slot.Operation)
				if e != nil || slotKey != key || slot.Generation < 1 || slot.Generation > state.Generation || !managedUUID.MatchString(slot.Execution) || !managedAttempt.MatchString(slot.claims().Attempt) || !managedHash.MatchString(slot.claims().Digest) {
					err = errors.New("invalid managed slot evidence")
				}
			}
		default:
			err = errors.New("missing managed evidence")
		}
	}
	return state, err
}

func slotCommand(slot *ownerSlot, gen int64) map[string]any {
	return map[string]any{"operation": slot.Operation, "generation": gen}
}

func (o *managedOwner) submit(ctx context.Context, key string, s *ownerSlot, gen int64) (ownerState, error) {
	var ack struct {
		Status    string
		Execution string `json:"execution_id"`
		Digest    string
	}
	cmd := slotCommand(s, gen)
	err := o.client.call(ctx, "submit", cmd, &ack)
	if err != nil {
		return ownerState{}, err
	}
	if ack.Status != "broker_ack" || ack.Execution != s.Execution || ack.Digest != s.claims().Digest {
		return ownerState{}, errors.New("managed broker handoff unconfirmed")
	}
	return o.state(ctx, "ack", cmd, key)
}

func (o *managedOwner) publish(ctx context.Context, raw json.RawMessage, a *alert.Alert) (string, error) {
	var op managedClaims
	if !o.ready.Load() || json.Unmarshal(raw, &op) != nil || a.StartsAt.After(time.Now()) {
		return "", errors.New("managed worker unavailable")
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(op.Deadline, 0))
	defer cancel()
	key, err := boundKey(raw)
	if err != nil {
		return "", err
	}
	// The in-flight bit only claims this operation. No mutex is held during I/O.
	var g *managedGate
	var release func()
	for {
		g, release, err = o.enter(key)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
	defer release()
	cmd := map[string]any{"operation": raw}
	state, err := o.state(ctx, "lookup", cmd, key)
	if err != nil {
		return "", err
	}
	if state.Generation > 0 && state.Phase != "archived" {
		g.durable = true
	}
	if state.Closed != nil && op.Kind != "clear" {
		return "episode_closed", nil
	}
	for state.Pending != nil && state.Pending.claims().EventID != op.EventID {

		if err = o.recover(ctx, key, g, state); err != nil {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
		state, err = o.state(ctx, "lookup", cmd, key)
		if err != nil {
			return "", err
		}
		if state.Closed != nil && op.Kind != "clear" {
			return "episode_closed", nil
		}
	}
	isCurrent := state.Current != nil && state.Current.claims().EventID == op.EventID
	if !isCurrent && state.Pending == nil {
		// SQL and the process epoch preserve an uncertain reservation across gate release.
		cmd["native_epoch"] = o.epoch
		cmd["generation"] = op.Expected
		cmd["projection"] = snapshot(a)
		state, err = o.state(ctx, "reserve", cmd, key)
		if err != nil {
			return "", err
		}
		g.durable = state.Phase != "archived"
		if state.Replay {
			fresh, e := o.state(ctx, "lookup", map[string]any{"operation": raw}, key)
			if e != nil {
				return "", e
			}
			if fresh.Closed != nil && op.Kind != "clear" {
				return "episode_closed", nil
			}
			return "forwarded", nil
		}
		if state.Closed != nil {
			return "episode_closed", nil
		}
	}
	slot := state.Pending
	if isCurrent {
		slot = state.Current
	}
	if slot == nil || slot.claims().Digest != op.Digest || slot.claims().EventID != op.EventID {
		return "", errors.New("managed slot mismatch")
	}
	pending := state.Pending != nil && state.Pending.Execution == slot.Execution
	if !isCurrent && slot.claims().Attempt != op.Attempt && state.Phase == "reserved" {
		return "", errors.New("existing managed attempt pending")
	}
	if state.Closed == nil {
		if isCurrent {
			frozen, e := slot.Projection.restore()
			if e != nil {
				return "", e
			}
			if frozen.Fingerprint() != a.Fingerprint() || !frozen.StartsAt.Equal(a.StartsAt) {
				return "", errors.New("managed refresh changed native pair")
			}
			if frozen.Timeout && a.EndsAt.After(frozen.EndsAt) {
				frozen.EndsAt = a.EndsAt
				frozen.UpdatedAt = a.UpdatedAt
			}
			a = frozen
		}
		o.attachMember(a, key, slot)
		err = o.store.ApplyManaged(ctx, key, a, slot.stamp(), func() error {
			if ctx.Err() != nil || time.Now().Unix() >= op.Deadline {
				return errors.New("managed native deadline")
			}
			if g.appliedGeneration > state.Generation {
				return errors.New("managed stale generation")
			}
			return nil
		})
		if err != nil {
			if state.Phase == "reserved" {
				g.provenUnapplied = slot.claims().Attempt
			}
			return "", err
		}
		g.appliedGeneration, g.appliedAttempt = state.Generation, slot.claims().Attempt
		if isCurrent && a.Timeout && a.EndsAt.After(slot.Projection.Alert.EndsAt) {
			state, err = o.state(ctx, "renew", map[string]any{"operation": raw, "generation": state.Generation, "ends_at": a.EndsAt.UTC()}, key)
			if err != nil {
				return o.recheckClosed(ctx, key, raw, g, err)
			}
		}
	}
	if state.Phase == "reserved" {
		state, err = o.state(ctx, "applied", slotCommand(slot, state.Generation), key)
		if err != nil {
			return o.recheckClosed(ctx, key, raw, g, err)
		}
	}
	if pending && state.Phase != "ack" {
		if _, err = o.submit(ctx, key, slot, state.Generation); err != nil {
			return o.recheckClosed(ctx, key, raw, g, err)
		}
	}
	state, err = o.state(ctx, "lookup", map[string]any{"operation": raw}, key)
	if err != nil {
		return o.recheckClosed(ctx, key, raw, g, err)
	}
	if state.Phase == "closing" || state.Closed != nil && op.Kind != "clear" {
		if err = o.recover(ctx, key, g, state); err != nil {
			return "", err
		}
		return "episode_closed", nil
	}
	if state.Current == nil || state.Current.Execution != slot.Execution || (state.Pending != nil && state.Phase != "ack") {
		return "", errors.New("managed forwarding unconfirmed")
	}
	if isCurrent && state.Closed == nil && a.Timeout && state.Current.Projection.Alert.EndsAt.Before(a.EndsAt) {
		return "", errors.New("managed renewal unconfirmed")
	}
	return "forwarded", nil
}

// A manual close may win after the provider commit, including when the SQL
// promotion or the submission reply is lost. Compensate through its fenced
// generation independently of expiry of the original source authorization.
func (o *managedOwner) recheckClosed(ctx context.Context, key string, raw json.RawMessage, g *managedGate, cause error) (string, error) {
	check, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	s, err := o.state(check, "lookup", map[string]any{"operation": raw}, key)
	if err == nil && s.Closed != nil && s.Phase == "closing" {
		if err = o.recover(check, key, g, s); err == nil {
			return "episode_closed", nil
		}
	}
	return "", cause
}

func (o *managedOwner) recover(ctx context.Context, key string, g *managedGate, s ownerState) error {
	if (s.Phase == "retired" || s.Phase == "closed") && s.Closed != nil && time.Now().UnixMilli() >= *s.Closed+15000 {
		// A terminal clear is itself an ordinary native alert. Group wait and
		// repeat intervals can outlive the SQL stale-write barrier. Preserve its
		// pinned callback until the provider can no longer authenticate that member.
		if current := s.Current; current != nil && current.Generation == s.Generation && current.claims().Kind == "clear" {
			if current.Projection.Alert.EndsAt.After(time.Now()) {
				return nil
			}
			member, lookupErr := o.store.Get(current.Projection.Alert.Fingerprint())
			if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
				return lookupErr
			}
			if member != nil && member.ManagedMember.Episode == key && member.ManagedMember.Generation == s.Generation {
				return nil
			}
		}
		out, err := o.state(ctx, "compact", map[string]any{"key": key, "generation": s.Generation}, key)
		if err == nil && out.Phase == "archived" {
			o.store.ReleaseManaged(key, s.Generation)
			g.durable = false
		}
		return err
	}
	slot := s.Pending
	if slot == nil {
		slot = s.Current
	}
	if slot == nil {
		return nil
	}
	cmd := slotCommand(slot, s.Generation)
	if s.Phase == "closing" {
		err := o.store.ApplyManaged(ctx, key, nil, provider.ManagedStamp{Generation: s.Generation, Attempt: "closed", Digest: slot.claims().Digest}, func() error { return ctx.Err() })
		if err != nil {
			return err
		}
		g.appliedGeneration = s.Generation
		_, err = o.state(ctx, "retired", cmd, key)
		return err
	}
	if s.Phase == "reserved" {
		if applied, ok := o.store.ManagedApplied(key); ok && applied == slot.stamp() {
			_, err := o.state(ctx, "applied", cmd, key)
			return err
		}
		if (g.provenUnapplied == slot.claims().Attempt || (slot.Epoch == o.epoch && o.epoch != "")) && time.Now().Unix() >= slot.claims().Deadline+5 {
			_, err := o.state(ctx, "cancel-unapplied", cmd, key)
			return err
		}
		// Prior-epoch memory may have been briefly visible. Once the
		// sole replacement has restored authority, a still-reserved slot
		// could not have been handed to the broker. Compare its independent
		// current stamp before superseding the old generation.
		if o.restored.Load() && slot.Epoch != o.epoch && time.Now().Unix() >= slot.claims().Deadline+5 {
			actual, present := o.store.ManagedApplied(key)
			if (s.Current == nil && !present) || (s.Current != nil && present && actual == s.Current.stamp()) {
				priorGeneration := int64(0)
				if s.Current != nil {
					priorGeneration = s.Current.Generation
				}
				cmd["current_generation"], cmd["native_epoch"] = priorGeneration, o.epoch
				_, err := o.state(ctx, "cancel-unpromoted", cmd, key)
				return err
			}
		}
		return errors.New("managed reservation unresolved")
	}
	if s.Pending == nil {
		return nil
	}
	recovered, err := o.state(ctx, "recover", cmd, key)
	if err == nil && recovered.Redrive {
		_, err = o.submit(ctx, key, slot, s.Generation)
	}
	return err
}

// The SQL observation can advance independently of a blocked provider handoff.
// Hold readiness on incomplete startup restoration, but visit the rest of every
// page and retry failed restoration on the next pass.
func (o *managedOwner) maintainEpisode(ctx context.Context, key string, restore bool) error {
	g, release, err := o.enter(key)
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	lookup := func() (ownerState, error) { return o.state(ctx, "lookup", map[string]string{"key": key}, key) }
	s, err := lookup()
	if err != nil {
		return err
	}
	g.durable = s.Generation > 0 && s.Phase != "archived"
	if !restore {
		return o.recover(ctx, key, g, s)
	}
	if s.Phase == "reserved" && s.Pending != nil {
		if applied, ok := o.store.ManagedApplied(key); ok && applied == s.Pending.stamp() {
			if err = o.recover(ctx, key, g, s); err != nil {
				return err
			}
			if s, err = lookup(); err != nil {
				return err
			}
		} else {
			// Ambiguous prior-epoch reservations remain fenced in SQL. A
			// provably unapplied attempt can be cancelled after its deadline.
			_ = o.recover(ctx, key, g, s)
		}
	}
	if s.Phase == "closing" || s.Phase == "closed" || s.Phase == "retired" {
		if err = o.recover(ctx, key, g, s); err != nil {
			return err
		}
		if s, err = lookup(); err != nil {
			return err
		}
	} else if s.Pending != nil && (s.Phase == "applied" || s.Phase == "ack") {
		// A missing worker must not erase a provably committed native projection.
		workerCtx, cancelWorker := context.WithTimeout(ctx, time.Second)
		_ = o.recover(workerCtx, key, g, s)
		cancelWorker()
		if s, err = lookup(); err != nil {
			return err
		}
	}
	if s.Current == nil || (s.Closed != nil && (s.Current.claims().Kind != "clear" || s.Current.Generation != s.Generation)) {
		return nil
	}
	a, err := s.Current.Projection.restore()
	if err != nil {
		return err
	}
	o.attachMember(a, key, s.Current)
	if err = o.store.ApplyManaged(ctx, key, a, s.Current.stamp(), func() error { return ctx.Err() }); err != nil {
		return err
	}
	g.appliedGeneration, g.appliedAttempt = s.Current.Generation, s.Current.claims().Attempt
	return nil
}

func (o *managedOwner) maintain() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-o.store.ManagedShutdown():
			cancel()
		case <-ctx.Done():
		}
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	restore := true
	restoreFailed := false
	cursor := ""
	for {
		var capability struct {
			Contract       string
			Worker         bool
			Rows, Capacity int
		}
		err := o.client.call(ctx, "capability", map[string]any{}, &capability)
		compatible := err == nil && capability.Contract == managedContract && capability.Capacity == maxManagedRows && capability.Rows <= maxManagedRows
		healthy := compatible
		if compatible {
			var page struct{ Keys []string }
			err = o.client.call(ctx, "scan", map[string]any{"after": cursor, "restore": restore}, &page)
			healthy = err == nil && page.Keys != nil && len(page.Keys) <= 32
			if healthy {
				for _, key := range page.Keys {
					if !managedHash.MatchString(key) || key <= cursor {
						healthy = false
						break
					}
					if e := o.maintainEpisode(ctx, key, restore); e != nil && restore {
						restoreFailed = true
					}
					cursor = key
				}
				if healthy && len(page.Keys) < 32 {
					restore = restore && restoreFailed
					if !restore {
						o.restored.Store(true)
					}
					restoreFailed = false
					cursor = ""
				}
			}
		}
		o.ready.Store(healthy && capability.Worker && !restore)
		// A slow pass must leave a retry interval for ordinary source admission.
		timer.Reset(time.Second)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

func (o *managedOwner) read(ctx context.Context, raw json.RawMessage, confirm bool) (map[string]any, error) {
	var op managedClaims
	if !o.ready.Load() || json.Unmarshal(raw, &op) != nil {
		return nil, errors.New("managed capability unavailable")
	}
	key, err := boundKey(raw)
	if err != nil {
		return nil, err
	}
	g, release, err := o.enter(key)
	if err != nil {
		return nil, err
	}
	defer release()
	state, err := o.state(ctx, "lookup", map[string]any{"operation": raw}, key)
	if err != nil {
		return nil, err
	}
	g.durable = state.Generation > 0 && state.Phase != "archived"
	if state.State == "reserved" || (confirm && op.Expected != state.Generation) || time.Now().Unix() >= op.Deadline {
		return nil, errors.New("managed lookup busy or stale")
	}
	return map[string]any{"contract": managedContract, "state": state.State, "generation": state.Generation}, nil
}

// verifyActionMember joins the provider stamp to the currently promoted private owner slot.
func (o *managedOwner) verifyActionMember(ctx context.Context, a *alert.Alert, logical string) error {
	m := a.ManagedMember
	s, err := o.state(ctx, "lookup", map[string]string{"key": m.Episode}, m.Episode)
	if err != nil {
		return unavailable
	}
	return actionMemberProof(s, a, logical)
}

var discardedManagedMember = errors.New("managed observation superseded or cancelled")

type closedManagedOwner struct {
	key        string
	generation int64
}

func (closedManagedOwner) Error() string { return "authoritative managed closure" }

func actionMemberProof(s ownerState, a *alert.Alert, logical string) error {
	m := a.ManagedMember
	if s.Key != m.Episode {
		return unverified
	}
	if s.State == "exact_closed" && s.Closed != nil && s.Generation > m.Generation && (s.Phase == "closing" || s.Phase == "retired" || s.Phase == "closed") && (s.Current == nil || s.Current.claims().Kind != "clear" || s.Current.Generation != s.Generation) {
		return closedManagedOwner{s.Key, s.Generation}
	}
	slot := s.Current
	if slot == nil || slot.Generation != m.Generation {
		if s.Phase == "cancelled" && s.Pending == nil && m.Generation <= s.Generation || slot != nil && slot.Generation > m.Generation {
			return discardedManagedMember
		}
		return unverified
	}
	if slot.claims().Kind != a.ManagedOperationKind || slot.claims().EventID != m.Event || slot.claims().Digest != m.Digest || slot.Projection.Fingerprint != a.Fingerprint().String() || !slot.Projection.Alert.StartsAt.Equal(a.StartsAt) {
		return unverified
	}
	switch s.Phase {
	case "cancelled":
		if s.Pending != nil || s.Closed != nil || s.Generation <= m.Generation {
			return unverified
		}
	case "applied", "ack", "settled", "retired":
		if s.Generation != m.Generation {
			return unverified
		}
	default:
		return unverified
	}
	if a.ManagedOperationKind == "clear" {
		if s.Closed == nil || logical != "resolved" {
			return unverified
		}
		return nil
	}
	if s.Closed != nil {
		return resolved
	}
	if logical == "resolved" && a.EndsAt.Before(slot.Projection.Alert.EndsAt) {
		return discardedManagedMember
	}
	if logical == "resolved" && (!a.Resolved() || !a.EndsAt.Equal(slot.Projection.Alert.EndsAt)) {
		return unverified
	}
	return nil
}
