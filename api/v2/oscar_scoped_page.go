// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0.

package v2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/go-openapi/runtime"
	model "github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/alert"
	ops "github.com/prometheus/alertmanager/api/v2/restapi/operations/alert"
)

const scopedPagePath = "/api/v2/oscar/alerts/scoped-page"

type scopedReadDeadlineKey struct{}

// WithScopedPageReadDeadline preserves the transport deadline across http.TimeoutHandler.
func WithScopedPageReadDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != scopedPagePath {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		controller := http.NewResponseController(w)
		var mu sync.Mutex
		var reading bool
		set := func(t time.Time) error {
			mu.Lock()
			defer mu.Unlock()
			if controller == nil {
				return http.ErrHandlerTimeout
			}
			err := controller.SetReadDeadline(t)
			if err == nil {
				reading = !t.IsZero()
			}
			return err
		}
		defer func() {
			mu.Lock()
			defer mu.Unlock()
			// TimeoutHandler may return while its handler is still reading the body.
			if reading {
				_ = controller.SetReadDeadline(time.Now())
			}
			controller = nil
		}()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), scopedReadDeadlineKey{}, set)))
	})
}

// encoding/json replaces isolated UTF-16 surrogates with U+FFFD before typed validation.
func validScopeEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		if len(raw)-i < 5 {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if !utf16.IsSurrogate(rune(value)) {
			continue
		}
		if value >= 0xdc00 || len(raw)-i < 7 || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

type scopeGroup struct {
	Items []struct {
		Field    string          `json:"field"`
		Operator string          `json:"operator"`
		Value    json.RawMessage `json:"value"`
	} `json:"items"`
	Logic string `json:"logicOperator,omitempty"`
}

type scopeWire struct {
	Unrestricted bool         `json:"unrestricted"`
	Allow        []scopeGroup `json:"allow"`
	Deny         []scopeGroup `json:"deny"`
}

type pageScope struct {
	unrestricted bool
	allow, deny  []oscarGridModel
}

func (s scopeWire) compile() (*pageScope, error) {
	invalid := errors.New("invalid scoped-page policy")
	if s.Allow == nil || s.Deny == nil || len(s.Allow)+len(s.Deny) > 32 || s.Unrestricted && len(s.Allow) > 0 {
		return nil, invalid
	}
	count := 0
	compile := func(groups []scopeGroup) ([]oscarGridModel, error) {
		var result []oscarGridModel
		for _, group := range groups {
			if len(group.Items) == 0 {
				return nil, invalid
			}
			count += len(group.Items)
			if count > 100 {
				return nil, invalid
			}
			for _, item := range group.Items {
				name, ok := strings.CutPrefix(item.Field, "label:")
				if !ok || name == "" || strings.TrimSpace(name) != name {
					return nil, invalid
				}
				switch item.Operator {
				case "equals":
					var value *string
					if json.Unmarshal(item.Value, &value) != nil || value == nil || len(*value) > 4096 {
						return nil, invalid
					}
				case "isAnyOf":
					var values []*string
					if json.Unmarshal(item.Value, &values) != nil || len(values) == 0 || len(values) > 100 {
						return nil, invalid
					}
					for _, value := range values {
						if value == nil || len(*value) > 4096 {
							return nil, invalid
						}
					}
				default:
					return nil, invalid
				}
			}
			raw, err := json.Marshal(group)
			if err != nil {
				return nil, invalid
			}
			grid, err := parseOscarGridModel(string(raw))
			if err != nil {
				return nil, err
			}
			result = append(result, grid)
		}
		return result, nil
	}
	allow, err := compile(s.Allow)
	if err != nil {
		return nil, err
	}
	deny, err := compile(s.Deny)
	if err != nil {
		return nil, err
	}
	return &pageScope{s.Unrestricted, allow, deny}, nil
}

func (s *pageScope) matches(source *alert.Alert, fold *oscarCaseFolder) bool {
	if s.unrestricted && len(s.deny) == 0 {
		return true
	}
	// Child events also carry rule, window, pattern and parent-fingerprint labels.
	labels := source.Labels
	if role, ok := labels["oscar_correlation_role"]; ok && role != "child" {
		return false
	}
	if strings.HasPrefix(string(labels["oscar_correlation_event_type"]), "parent_") {
		return false
	}
	for _, key := range []model.LabelName{"oscar_synthetic_source", "correlation_parent_identity", "oscar_correlation_child_fingerprints", "oscar_correlation_child_fingerprints_omitted", "oscar_correlation_member_count", "oscar_correlation_active_count", "oscar_correlation_recovered_count"} {
		if _, present := labels[key]; present {
			return false
		}
	}
	if _, present := source.Annotations["oscar_correlation_impact"]; present {
		return false
	}
	matches := func(g oscarGridModel) bool {
		return g.matchesWithFold(source, alert.AlertStatus{}, "", time.Time{}, fold)
	}
	return (s.unrestricted || slices.ContainsFunc(s.allow, matches)) && !slices.ContainsFunc(s.deny, matches)
}

func (api *API) scopedPageRoutes(next http.Handler, key []byte) http.Handler {
	inFlight := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != scopedPagePath {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(405)
			return
		}
		hdr := func(name string) string {
			values := r.Header.Values("X-Oscar-Read-" + name)
			if len(values) != 1 {
				return ""
			}
			return values[0]
		}
		if len(key) < 32 || hdr("Sender") != "operator" || hdr("Key-Id") != "v1" || hdr("Grant") != "read:alerts" ||
			r.URL.ForceQuery || r.URL.RawQuery != "" || r.URL.RawPath != "" || len(r.Header.Values("Content-Encoding")) != 0 {
			w.WriteHeader(401)
			return
		}
		stamp, subject := hdr("Time"), hdr("Subject")
		if len(subject) > 1360 || len(hdr("Signature")) != 64 {
			w.WriteHeader(401)
			return
		}
		id, err := base64.RawURLEncoding.Strict().DecodeString(subject)
		if err != nil || len(id) == 0 || !utf8.Valid(id) || utf8.RuneCount(id) > 255 || base64.RawURLEncoding.EncodeToString(id) != subject {
			w.WriteHeader(401)
			return
		}
		sec, err := strconv.ParseInt(stamp, 10, 64)
		now := time.Now()
		if err != nil || strconv.FormatInt(sec, 10) != stamp || sec < now.Unix()-60 || sec > now.Unix()+5 {
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
		setDeadline, ok := r.Context().Value(scopedReadDeadlineKey{}).(func(time.Time) error)
		if !ok {
			setDeadline = http.NewResponseController(w).SetReadDeadline
		}
		deadline := now.Add(5 * time.Second)
		if end, ok := r.Context().Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := setDeadline(deadline); err != nil {
			w.WriteHeader(503)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, actionBodyLimit+1))
		clearErr := setDeadline(time.Time{})
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			w.WriteHeader(http.StatusRequestTimeout)
			return
		}
		if clearErr != nil {
			w.WriteHeader(503)
			return
		}
		if err != nil || len(raw) > actionBodyLimit {
			w.WriteHeader(413)
			return
		}
		if sec < time.Now().Unix()-60 {
			w.WriteHeader(401)
			return
		}
		digest := sha256.Sum256(raw)
		mac := hmac.New(sha256.New, key)
		fmt.Fprintf(mac, "native-scoped-page-v1\n%s\n%s\noperator\nv1\n%s\n%s\nread:alerts\n%x", r.Method, r.URL.Path, stamp, subject, digest)
		sig, err := hex.DecodeString(hdr("Signature"))
		if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
			w.WriteHeader(401)
			return
		}
		var body struct {
			Version int        `json:"version"`
			Scope   scopeWire  `json:"scope"`
			Query   url.Values `json:"query"`
		}
		if !validScopeEscapes(raw) || !decodeAction(raw, &body) || body.Version != 1 || body.Query == nil {
			w.WriteHeader(400)
			return
		}
		for _, values := range body.Query {
			if len(values) == 0 || len(values) > 100 {
				w.WriteHeader(400)
				return
			}
		}
		policy, err := body.Scope.compile()
		if err != nil {
			w.WriteHeader(400)
			return
		}
		result := api.oscarAlertsPage(ops.GetOscarAlertsPageParams{HTTPRequest: r}, body.Query, policy)
		if _, ok := result.(*ops.GetOscarAlertsPageOK); ok {
			w.Header().Set("X-Oscar-Scoped-Page-Version", "1")
		}
		w.Header().Set("Content-Type", "application/json")
		result.WriteResponse(w, runtime.JSONProducer())
	})
}
