// Copyright 2018 Prometheus Team
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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const conversionAnnotation = "__oscar_fingerprint_conversion"

type conversionActorKey struct{}
type managedReadKey struct{}

const managedReadPath = "/api/v2/oscar/managed-episode/status"
const managedConfirmPath = "/api/v2/oscar/managed-episode/confirm"

func conversionActor(ctx context.Context) string {
	actor, _ := ctx.Value(conversionActorKey{}).(string)
	return actor
}

// InstallConversionAdmission installs confined producer admission before serving.
// Empty keys still scrub ordinary writes and advertise no enrolled producers.
func (api *API) InstallConversionAdmission(keys map[string][]byte, callbackKey ...[]byte) {
	if len(callbackKey) > 0 {
		api.conversionCallbackKey = bytes.Clone(callbackKey[0])
	}
	copied := make(map[string][]byte, len(keys))
	for name, key := range keys {
		copied[name] = bytes.Clone(key)
	}
	if api.conversionAdmissionHandler == nil {
		api.conversionAdmissionHandler = api.Handler
	}
	api.Handler = conversionAdmissionGuard(api.conversionAdmissionHandler, copied, api.conversionCallbackReady)
}

func conversionAdmissionGuard(next http.Handler, keys map[string][]byte, ready ...func() bool) http.Handler {
	callbackReady := func() bool { return len(ready) == 0 || ready[0]() }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/v2/oscar/fingerprint-conversion-capability" {
			actors := make([]string, 0, len(keys))
			for name := range keys {
				actors = append(actors, name)
			}
			sort.Strings(actors)
			w.Header().Set("Content-Type", "application/json")
			callback := ""
			if callbackReady() {
				callback = "native-conversion-callback-v1"
			}
			json.NewEncoder(w).Encode(map[string]any{"contract": "native-conversion-ingress-v1", "actors": actors, "callback_contract": callback})
			return
		}
		path := r.URL.Path
		readManaged := path == managedReadPath || path == managedConfirmPath
		if r.Method != "POST" || (path != "/api/v2/alerts" && !readManaged) {
			next.ServeHTTP(w, r)
			return
		}
		names := []string{"X-Oscar-Conversion-Actor", "X-Oscar-Conversion-Key-Id", "X-Oscar-Conversion-Time", "X-Oscar-Conversion-Signature"}
		present := false
		for _, name := range names {
			if len(r.Header.Values(name)) > 0 {
				present = true
			}
		}
		if !present {
			if readManaged {
				http.Error(w, "managed source assertion required", 401)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		for _, name := range names {
			if len(r.Header.Values(name)) != 1 || r.Header.Get(name) == "" {
				http.Error(w, "invalid conversion admission", 401)
				return
			}
		}
		actor, kid, stamp := r.Header.Get(names[0]), r.Header.Get(names[1]), r.Header.Get(names[2])
		seconds, err := strconv.ParseInt(stamp, 10, 64)
		key, exists := keys[actor+"/"+kid]
		if err != nil || strconv.FormatInt(seconds, 10) != stamp || seconds < time.Now().Unix()-60 || seconds > time.Now().Unix()+5 || !exists || len(key) < 32 || r.URL.RawQuery != "" || r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "invalid conversion admission", 401)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024+1))
		if err != nil || len(body) > 8*1024*1024 {
			http.Error(w, "invalid conversion body", 413)
			return
		}
		// A slow sender cannot keep an otherwise valid assertion alive while the
		// bounded exact body is read. Admission time is checked again at handoff.
		if seconds < time.Now().Unix()-60 || seconds > time.Now().Unix()+5 {
			http.Error(w, "invalid conversion admission", 401)
			return
		}
		sum := sha256.Sum256(body)
		message := strings.Join([]string{"native-conversion-ingress-v1", "POST", path, actor, kid, stamp, hex.EncodeToString(sum[:])}, "\n")
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(message))
		signature, err := hex.DecodeString(r.Header.Get(names[3]))
		if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
			http.Error(w, "invalid conversion admission", 401)
			return
		}
		if actor != "alertmanager-resolution" && !callbackReady() {
			http.Error(w, "native conversion callback unavailable", 503)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), conversionActorKey{}, actor)
		if readManaged {
			ctx = context.WithValue(ctx, managedReadKey{}, path)
			r = r.Clone(ctx)
			r.URL.Path = "/api/v2/alerts"
			r.URL.RawPath = ""
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func capsuleProducer(value string) string {
	var capsule struct {
		Claims struct {
			Producer string `json:"producer"`
		} `json:"claims"`
	}
	if err := json.Unmarshal([]byte(value), &capsule); err != nil {
		return ""
	}
	return capsule.Claims.Producer
}

func (api *API) conversionCallbackReady() bool {
	api.mtx.RLock()
	cfg := api.alertmanagerConfig
	key := bytes.Clone(api.conversionCallbackKey)
	api.mtx.RUnlock()
	if cfg == nil || len(key) < 32 || len(cfg.Receivers) == 0 {
		return false
	}
	for _, receiver := range cfg.Receivers {
		if len(receiver.WebhookConfigs) == 0 {
			return false
		}
		if api.managedOwner != nil {
			// A commissioned route may deliver only via the canonical eligibility-aware webhook.
			// JSON omitempty covers integrations added by future upstream versions as well.
			configured, err := json.Marshal(receiver)
			var fields map[string]json.RawMessage
			if err != nil || json.Unmarshal(configured, &fields) != nil || len(receiver.WebhookConfigs) != 1 {
				return false
			}
			for field := range fields {
				if strings.HasSuffix(field, "_configs") && field != "webhook_configs" {
					return false
				}
			}
		}
		for _, webhook := range receiver.WebhookConfigs {
			target, err := url.Parse(string(webhook.URL))
			if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" ||
				target.Path != "/api/v1/internal/fingerprint-conversion/alerts" || strings.ContainsAny(string(webhook.URL), "{}") ||
				webhook.HTTPConfig == nil || webhook.HTTPConfig.Authorization == nil || webhook.HTTPConfig.Authorization.Type != "Bearer" ||
				webhook.HTTPConfig.Authorization.CredentialsFile == "" || webhook.MaxAlerts != 0 || webhook.Payload != nil || !webhook.SendResolved() {
				return false
			}
			if owner := api.managedOwner; owner != nil {
				cfg := webhook.HTTPConfig
				if target.Scheme != owner.client.scheme || target.Host != "alertmanager-middleware:9400" || target.User != nil ||
					target.Fragment != "" || target.RawPath != "" || (target.RawQuery != "" && target.RawQuery != "notifier_type=oscaradmin") ||
					cfg.FollowRedirects || (target.Scheme == "https" && (cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.CAFile != owner.client.caFile ||
					(cfg.TLSConfig.ServerName != "" && cfg.TLSConfig.ServerName != "alertmanager-middleware"))) {
					return false
				}
			}
			actual, err := os.ReadFile(webhook.HTTPConfig.Authorization.CredentialsFile)
			if err != nil || !hmac.Equal(bytes.TrimSpace(actual), key) {
				return false
			}
		}
	}
	return true
}
