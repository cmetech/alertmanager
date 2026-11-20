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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"
)

func conversionRequest(body []byte, actor string, key []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v2/alerts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	timestamp := fmt.Sprint(time.Now().Unix())
	sum := sha256.Sum256(body)
	message := "native-conversion-ingress-v1\nPOST\n/api/v2/alerts\n" + actor + "\nv1\n" + timestamp + "\n" + hex.EncodeToString(sum[:])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	req.Header.Set("X-Oscar-Conversion-Actor", actor)
	req.Header.Set("X-Oscar-Conversion-Key-Id", "v1")
	req.Header.Set("X-Oscar-Conversion-Time", timestamp)
	req.Header.Set("X-Oscar-Conversion-Signature", hex.EncodeToString(mac.Sum(nil)))
	return req
}

func TestConversionAdmissionExactRequest(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte("w"), 32)
	body := []byte(`[{"labels":{"alertname":"A"}}]`)
	called := false
	guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		require.Equal(t, "webhookreceiver", conversionActor(r.Context()))
		w.WriteHeader(200)
	}), map[string][]byte{"webhookreceiver/v1": key})
	reply := httptest.NewRecorder()
	guard.ServeHTTP(reply, conversionRequest(body, "webhookreceiver", key))
	require.Equal(t, 200, reply.Code)
	require.True(t, called)
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("X-Oscar-Conversion-Actor", "webhookreceiver") },
		func(r *http.Request) { r.Header.Set("X-Oscar-Conversion-Actor", "trapreceiver") },
		func(r *http.Request) { r.Header.Set("X-Oscar-Conversion-Time", "0") },
		func(r *http.Request) { r.Body = http.NoBody },
		func(r *http.Request) { r.Header.Set("X-Oscar-Conversion-Signature", "copied") },
	} {
		called = false
		req := conversionRequest(body, "webhookreceiver", key)
		mutate(req)
		reply := httptest.NewRecorder()
		guard.ServeHTTP(reply, req)
		require.Equal(t, 401, reply.Code)
		require.False(t, called)
	}
}

func TestConversionAdmissionOrdinaryAndUnconfigured(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte("w"), 32)
	guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Empty(t, conversionActor(r.Context()))
		w.WriteHeader(200)
	}), nil)
	reply := httptest.NewRecorder()
	guard.ServeHTTP(reply, httptest.NewRequest("POST", "/api/v2/alerts", bytes.NewReader([]byte("[]"))))
	require.Equal(t, 200, reply.Code)
	reply = httptest.NewRecorder()
	guard.ServeHTTP(reply, conversionRequest([]byte("[]"), "webhookreceiver", key))
	require.Equal(t, 401, reply.Code)
}

func TestConversionInstallationRetainsSilenceGuard(t *testing.T) {
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry(), bytes.Repeat([]byte("s"), 32))
	require.NoError(t, err)
	api.InstallConversionAdmission(map[string][]byte{"webhookreceiver/v1": bytes.Repeat([]byte("w"), 32)})
	reply := httptest.NewRecorder()
	api.Handler.ServeHTTP(reply, httptest.NewRequest("POST", "/api/v2/silences", bytes.NewReader([]byte("{}"))))
	require.Equal(t, 403, reply.Code)
}

func TestConversionAdmissionRequiresInstalledCallback(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte("w"), 32)
	called := false
	guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }),
		map[string][]byte{"webhookreceiver/v1": key}, func() bool { return false })
	reply := httptest.NewRecorder()
	guard.ServeHTTP(reply, conversionRequest([]byte("[]"), "webhookreceiver", key))
	require.Equal(t, 503, reply.Code)
	require.False(t, called)
}

type delayedConversionBody struct {
	io.ReadCloser
	delayed bool
}

func (b *delayedConversionBody) Read(p []byte) (int, error) {
	if !b.delayed {
		b.delayed = true
		time.Sleep(61 * time.Second)
	}
	return b.ReadCloser.Read(p)
}

func TestConversionAdmissionExpiresWhileReadingBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := bytes.Repeat([]byte("w"), 32)
		request := conversionRequest([]byte("[]"), "webhookreceiver", key)
		request.Body = &delayedConversionBody{ReadCloser: request.Body}
		called := false
		guard := conversionAdmissionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }), map[string][]byte{"webhookreceiver/v1": key})
		reply := httptest.NewRecorder()
		guard.ServeHTTP(reply, request)
		require.Equal(t, 401, reply.Code)
		require.False(t, called)
	})
}
