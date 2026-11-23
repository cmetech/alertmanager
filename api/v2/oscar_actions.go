// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prometheus/alertmanager/alert"
)

const actionPath = "/api/v2/oscar/actions"
const actionBodyLimit = 256 << 10

type EpisodeRef = alert.EpisodeRef
type ScopeEntry = alert.TargetScopeEntry

type ActionActor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type PolicyBinding struct {
	BindingID              string `json:"binding_id"`
	RevisionID             string `json:"revision_id"`
	CancellationGeneration uint64 `json:"cancellation_generation"`
}
type ActionRequestV1 struct {
	Version        int            `json:"version"`
	OperationID    string         `json:"operation_id"`
	EpisodeRef     EpisodeRef     `json:"episode_ref"`
	Kind           string         `json:"kind"`
	TargetScope    []ScopeEntry   `json:"target_scope"`
	Actor          ActionActor    `json:"actor"`
	PolicyBinding  *PolicyBinding `json:"policy_binding"`
	TargetSeverity *string        `json:"target_severity"`
}
type DispatchTarget struct {
	ReceiverID        string       `json:"receiver_id"`
	IntegrationDigest string       `json:"integration_digest"`
	Scope             []ScopeEntry `json:"scope"`
	RepeatIntervalUS  int64        `json:"repeat_interval_us"`
}
type TargetResult struct {
	TargetKey   string         `json:"target_key"`
	Target      DispatchTarget `json:"target"`
	State       string         `json:"state"`
	Evidence    *string        `json:"evidence"`
	SuccessorID *string        `json:"successor_id"`
}
type ActionResultV1 struct {
	OperationID      string         `json:"operation_id"`
	State            string         `json:"state"`
	Reason           *string        `json:"reason"`
	EpisodeRef       EpisodeRef     `json:"episode_ref"`
	SeverityRevision uint64         `json:"severity_revision"`
	FloorApplied     *string        `json:"floor_applied"`
	PermitExpiresAt  *time.Time     `json:"permit_expires_at"`
	Targets          []TargetResult `json:"targets"`
}
type ActionDecision struct {
	Allowed bool    `json:"allowed"`
	Reason  *string `json:"reason"`
}
type Eligibility struct {
	SeverityRevision *uint64                   `json:"severity_revision"`
	EpisodeRef       EpisodeRef                `json:"episode_ref"`
	Actions          map[string]ActionDecision `json:"actions"`
}
type policyAssertionKey struct{}
type policyAssertion struct {
	Recovery  *policyRecovery
	ExpiresAt time.Time
}
type policyRecovery struct {
	Mode             string     `json:"mode"`
	CurrentRef       EpisodeRef `json:"current_ref"`
	SeverityRevision uint64     `json:"severity_revision"`
	TargetKeys       []string   `json:"target_keys"`
	PreviousPermit   *string    `json:"previous_permit_expires_at"`
}

func (q policyRecovery) valid() bool {
	if !validRef(q.CurrentRef) || q.TargetKeys == nil || len(q.TargetKeys) > 100 {
		return false
	}
	if q.Mode == "resume" {
		if len(q.TargetKeys) != 0 {
			return false
		}
		if q.PreviousPermit != nil {
			_, e := time.Parse(time.RFC3339Nano, *q.PreviousPermit)
			return e == nil
		}
		return true
	}
	if q.Mode != "transfer" || q.PreviousPermit != nil {
		return false
	}
	seen := map[string]bool{}
	for _, key := range q.TargetKeys {
		if !managedHash.MatchString(key) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

type ActionOwner interface {
	Execute(context.Context, ActionRequestV1) (ActionResultV1, error)
	Lookup(context.Context, string) (ActionResultV1, error)
	Eligibility(context.Context, []EpisodeRef) ([]Eligibility, error)
}

var actionGrants = map[string]string{"acknowledge": "update:alerts:acknowledge", "ticket_create": "update:alerts:ticket", "ticket_associate": "update:alerts:ticket", "escalate": "run:alerts:resend", "resend": "run:alerts:resend"}
var firingRanks = map[string]int{"info": 1, "minor": 2, "warning": 3, "major": 4, "critical": 5}

type actionError struct {
	code   int
	reason string
}

func (e actionError) Error() string { return e.reason }

var unavailable = actionError{503, "NATIVE_UNAVAILABLE"}
var mismatch = actionError{409, "NATIVE_EPISODE_MISMATCH"}
var unverified = actionError{409, "NATIVE_IDENTITY_UNVERIFIED"}
var resolved = actionError{409, "NATIVE_EPISODE_RESOLVED"}
var conflict = actionError{409, "ACTION_REQUEST_CONFLICT"}
var reconcile = actionError{409, "ACTION_RECONCILIATION_REQUIRED"}

func validRef(ref EpisodeRef) bool {
	return managedUUID.MatchString(ref.AuthorityID) && managedUUID.MatchString(ref.EpisodeID) && ref.Generation > 0 && ref.VariantRevision > 0
}
func validAction(req ActionRequestV1) bool {
	if req.Version != 1 || !validRef(req.EpisodeRef) || !managedUUID.MatchString(req.OperationID) || actionGrants[req.Kind] == "" || req.Actor.ID == "" || utf8.RuneCountInString(req.Actor.ID) > 255 || req.TargetScope == nil || len(req.TargetScope) > 100 {
		return false
	}
	if (req.TargetSeverity != nil) != (req.Kind == "escalate") || req.TargetSeverity != nil && firingRanks[*req.TargetSeverity] == 0 {
		return false
	}
	if (req.PolicyBinding != nil) != (req.Actor.Kind == "policy") || req.Actor.Kind != "policy" && req.Actor.Kind != "operator" {
		return false
	}
	if b := req.PolicyBinding; b != nil && (!managedUUID.MatchString(b.BindingID) || !managedUUID.MatchString(b.RevisionID) || req.Kind == "resend" && len(req.TargetScope) == 0 || !dispatchKind(req.Kind)) {
		return false
	}
	seen := map[[3]string]bool{}
	for _, s := range req.TargetScope {
		k := [3]string{s.ReceiverID, "", ""}
		if s.ReceiverID == "" || (s.Action == nil) != (s.NotifierID == nil) {
			return false
		}
		if s.Action != nil {
			k[1], k[2] = *s.NotifierID, *s.Action
			if !managedUUID.MatchString(k[1]) || k[2] != "ticket" && k[2] != "notification" {
				return false
			}
		}
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}
func dispatchKind(k string) bool { return k == "resend" || k == "escalate" }

// Decode one bounded tree, preserving 64-bit integers and rejecting duplicate object keys.
func actionJSON(d *json.Decoder, depth int) (any, error) {
	if depth > 16 {
		return nil, errors.New("excess nesting")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			name, e := d.Token()
			if e != nil {
				return nil, e
			}
			k, ok := name.(string)
			if _, dup := m[k]; !ok || dup {
				return nil, errors.New("duplicate or invalid key")
			}
			m[k], e = actionJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
		}
		_, e = d.Token()
		return m, e
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, e := actionJSON(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	}
	return t, nil
}
func decodeAction(raw []byte, out any) bool {
	if !utf8.Valid(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := actionJSON(dec, 0)
	if err != nil {
		return false
	}
	if _, err = dec.Token(); err != io.EOF {
		return false
	}
	if err = json.Unmarshal(raw, out); err != nil {
		return false
	}
	// Exact round trip enforces field spelling, required nullable fields and types.
	b, err := json.Marshal(out)
	if err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var check any
	return d.Decode(&check) == nil && reflect.DeepEqual(v, check)
}

func actionDigest(req ActionRequestV1) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var obj map[string]any
	if err = d.Decode(&obj); err != nil {
		return "", err
	}
	return canonicalActionDigest(obj)
}

// Both action requests and full-scope ordinary target keys use compact UTF-8 JSON.
func canonicalActionDigest(value any) (string, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(value); err != nil {
		return "", err
	}
	// Go sorts map keys but escapes these two Unicode runes even with HTML escaping off.
	// Skip escaped backslashes so a literal six-character escape stays literal.
	raw := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	h := sha256.New()
	for i := 0; i < len(raw); {
		if raw[i] == '\\' && i+1 < len(raw) {
			if bytes.HasPrefix(raw[i:], []byte(`\u2028`)) {
				h.Write([]byte("\u2028"))
				i += 6
				continue
			}
			if bytes.HasPrefix(raw[i:], []byte(`\u2029`)) {
				h.Write([]byte("\u2029"))
				i += 6
				continue
			}
			h.Write(raw[i : i+2])
			i += 2
			continue
		}
		j := bytes.IndexByte(raw[i+1:], '\\')
		if j < 0 {
			h.Write(raw[i:])
			break
		}
		h.Write(raw[i : i+j+1])
		i += j + 1
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func actionRoutes(next http.Handler, keys map[string][]byte, owner ActionOwner, ready func() bool) http.Handler {
	inFlight := make(chan struct{}, 32)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path != actionPath && !strings.HasPrefix(path, actionPath+"/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		read := path == actionPath+"/eligibility"
		lookup := strings.TrimPrefix(path, actionPath+"/")
		if path != actionPath && !read && !managedUUID.MatchString(lookup) {
			http.NotFound(w, r)
			return
		}
		if (path == actionPath || read) && r.Method != "POST" || path != actionPath && !read && r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(401)
			return
		}
		hdr := func(n string) string {
			values := r.Header.Values("X-Oscar-Action-" + n)
			if len(values) != 1 {
				return ""
			}
			return values[0]
		}
		sender, kid, stamp, subject, grant, sig := hdr("Sender"), hdr("Key-Id"), hdr("Time"), hdr("Subject"), hdr("Grant"), hdr("Signature")
		key := keys[sender]
		if len(key) < 32 || kid != "v1" || stamp == "" || grant == "" || subject == "" || sig == "" {
			w.WriteHeader(401)
			return
		}
		select {
		case inFlight <- struct{}{}:
			defer func() { <-inFlight }()
		default:
			w.WriteHeader(503)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, actionBodyLimit+1))
		if err != nil || len(body) > actionBodyLimit {
			w.WriteHeader(413)
			return
		}
		sec, err := strconv.ParseInt(stamp, 10, 64)
		now := time.Now().Unix()
		if err != nil || strconv.FormatInt(sec, 10) != stamp || sec < now-60 || sec > now+5 {
			w.WriteHeader(401)
			return
		}
		hash := sha256.Sum256(body)
		mac := hmac.New(sha256.New, key)
		parts := []string{"native-action-v1", r.Method, path, sender, kid, stamp, subject, grant}
		var recovery *policyRecovery
		extra := r.Header.Values("X-Oscar-Action-Recovery")
		if grant == "recover:policy" {
			if sender != "policy" || path != actionPath || r.Method != "POST" || len(extra) != 1 || len(extra[0]) > 11000 || sec < now-10 {
				w.WriteHeader(401)
				return
			}
			raw, e := base64.RawURLEncoding.Strict().DecodeString(extra[0])
			if e != nil || len(raw) > 8192 {
				w.WriteHeader(401)
				return
			}
			sum := sha256.Sum256(raw)
			parts = append(parts, hex.EncodeToString(sum[:]))
			recovery = &policyRecovery{}
			if !decodeAction(raw, recovery) || !recovery.valid() {
				w.WriteHeader(400)
				return
			}
		} else if len(extra) != 0 {
			w.WriteHeader(401)
			return
		}
		fmt.Fprint(mac, strings.Join(append(parts, hex.EncodeToString(hash[:])), "\n"))
		signature, err := hex.DecodeString(sig)
		if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
			w.WriteHeader(401)
			return
		}
		id, err := base64.RawURLEncoding.Strict().DecodeString(subject)
		if err != nil || len(id) == 0 || !utf8.Valid(id) || utf8.RuneCount(id) > 255 || sender == "policy" && string(id) != "resend-policy" {
			w.WriteHeader(403)
			return
		}
		var out any
		status := 200
		switch {
		case path == actionPath:
			var req ActionRequestV1
			if !decodeAction(body, &req) || !validAction(req) {
				w.WriteHeader(400)
				return
			}
			if req.Actor.ID != string(id) || req.Actor.Kind != sender || sender == "operator" && grant != actionGrants[req.Kind] || sender == "policy" && grant != "dispatch:policy" && grant != "recover:policy" || !dispatchKind(req.Kind) && len(req.TargetScope) > 0 {
				w.WriteHeader(403)
				return
			}
			if !ready() {
				err = unavailable
				break
			}
			var result ActionResultV1
			ctx := r.Context()
			if sender == "policy" {
				ctx = context.WithValue(ctx, policyAssertionKey{}, policyAssertion{Recovery: recovery, ExpiresAt: time.Unix(sec+10, 0)})
			}
			result, err = owner.Execute(ctx, req)
			out = result
			if result.State == "accepted" {
				status = 202
			} else if result.State == "held" || result.State == "rejected" || result.State == "superseded_no_effect" {
				status = 409
			}
		case read:
			if grant != "read:alerts" {
				w.WriteHeader(403)
				return
			}
			var batch struct {
				Refs []EpisodeRef `json:"refs"`
			}
			if !decodeAction(body, &batch) || batch.Refs == nil || len(batch.Refs) > 100 {
				w.WriteHeader(400)
				return
			}
			if !ready() {
				err = unavailable
				break
			}
			out, err = owner.Eligibility(r.Context(), batch.Refs)
		default:
			if len(body) != 0 || grant != "read:alerts" {
				w.WriteHeader(403)
				return
			}
			if owner == nil {
				err = unavailable
				break
			}
			out, err = owner.Lookup(r.Context(), lookup)
		}
		if err != nil {
			failure := unavailable
			errors.As(err, &failure)
			status = failure.code
			out = map[string]string{"reason": failure.reason}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	})
}
