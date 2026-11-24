// Copyright The Prometheus Authors
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

package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/route"
	"github.com/stretchr/testify/require"

	apiconnect "github.com/prometheus/alertmanager/api/connect"
	apiv2 "github.com/prometheus/alertmanager/api/v2"
	v2client "github.com/prometheus/alertmanager/api/v2/client"
	alertclient "github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/alertmanager/config"
	"github.com/prometheus/alertmanager/eventrecorder"
	"github.com/prometheus/alertmanager/labelset"
	"github.com/prometheus/alertmanager/provider/mem"
)

func TestConcurrencyLimitHandler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		var enteredOnce sync.Once
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()

		dst := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			w.WriteHeader(http.StatusNoContent)
		})
		api := &API{
			requestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: "test_requests_in_flight",
			}),
			concurrencyLimitExceeded: prometheus.NewCounter(prometheus.CounterOpts{
				Name: "test_concurrency_limit_exceeded_total",
			}),
			inFlightSem: make(chan struct{}, 1),
		}
		handler := api.concurrencyLimitHandler(dst)

		firstDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
			firstDone <- recorder
		}()
		<-entered

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		require.Equal(t, http.StatusServiceUnavailable, recorder.Code)

		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", nil))
		require.Equal(t, http.StatusNoContent, recorder.Code)

		unblock()
		first := <-firstDone
		require.Equal(t, http.StatusNoContent, first.Code)

		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		require.Equal(t, http.StatusNoContent, recorder.Code)
	})
}

func TestOptionsResolve(t *testing.T) {
	effective := (Options{
		Concurrency:                3,
		Timeout:                    time.Minute,
		ConnectStreamIdleTimeout:   -time.Second,
		ConnectStreamLifetime:      -time.Second,
		ConnectReadMaxBytes:        -1,
		ConnectSendMaxBytes:        -1,
		ConnectMaxRequestBodyBytes: -1,
	}).resolve()
	require.Equal(t, 3, effective.concurrency)
	require.Equal(t, time.Minute, effective.timeout)
	require.Equal(t, 3, effective.connect.UnaryConcurrency)
	require.Equal(t, 3, effective.connect.StreamConcurrency)
	require.Equal(t, time.Minute, effective.connect.UnaryTimeout)
	require.Zero(t, effective.connect.StreamIdleTimeout)
	require.Zero(t, effective.connect.StreamLifetime)
	require.Zero(t, effective.connect.ReadMaxBytes)
	require.Zero(t, effective.connect.SendMaxBytes)
	require.Zero(t, effective.connect.MaxRequestBodyBytes)

	effective = (Options{
		Concurrency:              3,
		Timeout:                  time.Minute,
		ConnectUnaryConcurrency:  4,
		ConnectStreamConcurrency: 5,
		ConnectUnaryTimeout:      -time.Second,
	}).resolve()
	require.Equal(t, 4, effective.connect.UnaryConcurrency)
	require.Equal(t, 5, effective.connect.StreamConcurrency)
	require.Zero(t, effective.connect.UnaryTimeout)
}

func TestConnectProceduresRegistered(t *testing.T) {
	for _, routePrefix := range []string{"/", "/alertmanager"} {
		t.Run(routePrefix, func(t *testing.T) {
			connectAPI := apiconnect.NewAPI(apiconnect.Options{})
			requestDuration := prometheus.NewHistogramVec(
				prometheus.HistogramOpts{Name: "test_registered_http_request_duration_seconds"},
				[]string{"handler", "method", "code"},
			)
			api := &API{
				v2:                &apiv2.API{Handler: http.NotFoundHandler()},
				connect:           connectAPI,
				deprecationRouter: NewV1DeprecationRouter(promslog.NewNopLogger()),
				requestDuration:   requestDuration,
				requestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
					Name: "test_registered_requests_in_flight",
				}),
				concurrencyLimitExceeded: prometheus.NewCounter(prometheus.CounterOpts{
					Name: "test_registered_concurrency_limit_exceeded_total",
				}),
				inFlightSem: make(chan struct{}, 1),
			}
			mux := api.Register(route.New(), routePrefix)
			mountPrefix := strings.TrimSuffix(routePrefix, "/") + "/api"

			for _, procedure := range connectAPI.Procedures() {
				t.Run(procedure, func(t *testing.T) {
					recorder := httptest.NewRecorder()
					request := httptest.NewRequest(http.MethodOptions, mountPrefix+procedure, nil)
					mux.ServeHTTP(recorder, request)
					require.NotEqual(t, http.StatusNotFound, recorder.Code)
				})
			}
		})
	}
}

// TestInstrumentConnectHandlerBoundsCardinality ensures that Connect/gRPC
// requests to unregistered paths collapse to a single placeholder handler
// label instead of being recorded verbatim, which would let a client inflate
// metric cardinality by hitting arbitrary paths.
func TestInstrumentConnectHandlerBoundsCardinality(t *testing.T) {
	const registeredProcedure = "/status.v3alpha.StatusService/GetStatus"

	for _, mountPrefix := range []string{"", "/alertmanager/api"} {
		t.Run(mountPrefix, func(t *testing.T) {
			reg := prometheus.NewRegistry()
			requestDuration := prometheus.NewHistogramVec(
				prometheus.HistogramOpts{Name: "test_http_request_duration_seconds"},
				[]string{"handler", "method", "code"},
			)
			reg.MustRegister(requestDuration)

			api := &API{requestDuration: requestDuration}

			// The inner handler isolates instrumentation behavior: 200 for the
			// registered procedure and 404 for every other path.
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == registeredProcedure {
					w.WriteHeader(http.StatusOK)
					return
				}
				http.NotFound(w, r)
			})
			h := api.instrumentConnectHandler(
				mountPrefix,
				[]string{registeredProcedure},
				http.StripPrefix(mountPrefix, inner),
			)

			for _, path := range []string{
				registeredProcedure,
				// Unknown methods on a known service must not each get their own
				// label; they collapse onto the unmatched placeholder.
				"/status.v3alpha.StatusService/Evil1",
				"/status.v3alpha.StatusService/Evil2",
				// Entirely unregistered paths collapse onto the placeholder.
				"/attacker/controlled/1",
				"/attacker/controlled/2",
			} {
				recorder := httptest.NewRecorder()
				h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, mountPrefix+path, nil))
			}

			families, err := reg.Gather()
			require.NoError(t, err)

			handlers := map[string]struct{}{}
			for _, fam := range families {
				if fam.GetName() != "test_http_request_duration_seconds" {
					continue
				}
				for _, m := range fam.GetMetric() {
					for _, lp := range m.GetLabel() {
						if lp.GetName() == "handler" {
							handlers[lp.GetValue()] = struct{}{}
						}
					}
				}
			}

			require.Equal(t, map[string]struct{}{
				registeredProcedure: {},
				unmatchedRPCLabel:   {},
			}, handlers)
		})
	}
}

type scopedDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *scopedDeadlineRecorder) SetReadDeadline(t time.Time) error {
	w.deadlines = append(w.deadlines, t)
	return nil
}

func newScopedPageTestAPI(t *testing.T, key string) *API {
	t.Helper()
	logger := promslog.NewNopLogger()
	store, err := mem.NewAlerts(t.Context(), time.Hour, 0, nil, logger, eventrecorder.NopRecorder(), prometheus.NewRegistry(), nil)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	v2, err := apiv2.NewAPI(store, nil, nil, nil, logger, prometheus.NewRegistry())
	require.NoError(t, err)
	keyfile := filepath.Join(t.TempDir(), "operator")
	require.NoError(t, os.WriteFile(keyfile, []byte(key), 0o600))
	require.NoError(t, v2.InstallActionOwner(apiv2.ActionOwnerConfig{OperatorKeyFile: keyfile}))
	cfg, err := config.Load("route:\n  receiver: team\nreceivers:\n- name: team\n")
	require.NoError(t, err)
	v2.Update(cfg, func(context.Context, labelset.LabelSet) {})
	api := API{v2: v2, timeout: time.Minute, connect: apiconnect.NewAPI(apiconnect.Options{}), deprecationRouter: NewV1DeprecationRouter(logger), requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_duration"}, []string{"handler", "method", "code"})}
	return &api
}

func TestScopedPageRegisteredWithWebTimeout(t *testing.T) {
	const path = "/api/v2/oscar/alerts/scoped-page"
	const key = "12345678901234567890123456789012"
	const body = `{"version":1,"scope":{"unrestricted":false,"allow":[],"deny":[]},"query":{}}`
	api := newScopedPageTestAPI(t, key)
	req := httptest.NewRequest(http.MethodPost, "/am"+path, strings.NewReader(body))
	stamp := fmt.Sprint(time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(key))
	fmt.Fprintf(mac, "native-scoped-page-v1\nPOST\n%s\noperator\nv1\n%s\nYWxpY2U\nread:alerts\n%x", path, stamp, sha256.Sum256([]byte(body)))
	for name, value := range map[string]string{"Sender": "operator", "Key-Id": "v1", "Time": stamp, "Subject": "YWxpY2U", "Grant": "read:alerts", "Signature": hex.EncodeToString(mac.Sum(nil))} {
		req.Header.Set("X-Oscar-Read-"+name, value)
	}
	w := &scopedDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	api.Register(route.New(), "/am").ServeHTTP(w, req)
	require.Equal(t, 200, w.Code, w.Body.String())
	require.Len(t, w.deadlines, 2)
	require.False(t, w.deadlines[0].IsZero())
	require.True(t, w.deadlines[1].IsZero())
}

func TestScopedPageOuterTimeoutHeaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Oscar-Scoped-Page-Version", "1")
			<-release
		})
		api := API{
			v2:                &apiv2.API{Handler: inner},
			timeout:           time.Second,
			connect:           apiconnect.NewAPI(apiconnect.Options{}),
			deprecationRouter: NewV1DeprecationRouter(promslog.NewNopLogger()),
			requestDuration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_timeout_duration"}, []string{"handler", "method", "code"}),
		}
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/am/api/v2/oscar/alerts/scoped-page", nil)
		api.Register(route.New(), "/am").ServeHTTP(w, req)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Equal(t, "no-store", w.Result().Header.Get("Cache-Control"))
		require.Empty(t, w.Result().Header.Values("X-Oscar-Scoped-Page-Version"))
	})
}

func TestScopedPageGeneratedClientOverHTTP(t *testing.T) {
	const key = "12345678901234567890123456789012"
	api := newScopedPageTestAPI(t, key)
	server := httptest.NewServer(api.Register(route.New(), "/am"))
	defer server.Close()
	client := v2client.NewHTTPClientWithConfig(nil, &v2client.TransportConfig{Host: strings.TrimPrefix(server.URL, "http://"), BasePath: "/am/api/v2", Schemes: []string{"http"}})
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport}
	for i, rule := range []*models.OscarPageScopeGroupItemsItems0{
		{Field: new("label:service"), Operator: new("equals"), Value: "Straße <ops> "},
		{Field: new("label:service"), Operator: new("isAnyOf"), Value: []string{"é", "billing"}},
	} {
		payload := &models.OscarScopedPageRequest{Version: new(int64(1)), Query: map[string][]string{}, Scope: &models.OscarScopedPageRequestScope{Unrestricted: new(false), Allow: []*models.OscarPageScopeGroup{{Items: []*models.OscarPageScopeGroupItemsItems0{rule}}}, Deny: []*models.OscarPageScopeGroup{}}}
		var wire bytes.Buffer
		require.NoError(t, runtime.JSONProducer().Produce(&wire, payload))
		stamp := fmt.Sprint(time.Now().Unix())
		mac := hmac.New(sha256.New, []byte(key))
		fmt.Fprintf(mac, "native-scoped-page-v1\nPOST\n/api/v2/oscar/alerts/scoped-page\noperator\nv1\n%s\nYWxpY2U\nread:alerts\n%x", stamp, sha256.Sum256(wire.Bytes()))
		reused := false
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
		params := alertclient.NewGetOscarScopedAlertsPageParamsWithContext(ctx)
		params.HTTPClient = httpClient
		params.Request = payload
		params.XOscarReadSender, params.XOscarReadKeyID, params.XOscarReadTime = "operator", "v1", stamp
		params.XOscarReadSubject, params.XOscarReadGrant, params.XOscarReadSignature = "YWxpY2U", "read:alerts", hex.EncodeToString(mac.Sum(nil))
		response, err := client.Alert.GetOscarScopedAlertsPage(params)
		require.NoError(t, err)
		require.Equal(t, "1", response.XOscarScopedPageVersion)
		require.EqualValues(t, 2, *response.Payload.ContractVersion)
		require.Zero(t, *response.Payload.TotalRecords)
		if i > 0 {
			require.True(t, reused, "second generated request must reuse the deadline-cleared connection")
		}
	}
}

func TestScopedPageStalledHTTPBodyIsBounded(t *testing.T) {
	for _, sender := range []string{"operator", "untrusted"} {
		t.Run(sender, func(t *testing.T) {
			const key = "12345678901234567890123456789012"
			api := newScopedPageTestAPI(t, key)
			server := httptest.NewServer(api.Register(route.New(), "/am"))
			defer server.Close()
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), time.Second)
			require.NoError(t, err)
			defer conn.Close()
			limit := 10 * time.Second
			if sender == "untrusted" {
				limit = 2 * time.Second
			}
			require.NoError(t, conn.SetDeadline(time.Now().Add(limit)))
			_, err = fmt.Fprintf(conn, "POST /am/api/v2/oscar/alerts/scoped-page HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\nContent-Length: 100\r\nX-Oscar-Read-Sender: %s\r\nX-Oscar-Read-Key-Id: v1\r\nX-Oscar-Read-Time: %d\r\nX-Oscar-Read-Subject: YWxpY2U\r\nX-Oscar-Read-Grant: read:alerts\r\nX-Oscar-Read-Signature: %s\r\n\r\n{", sender, time.Now().Unix(), strings.Repeat("0", 64))
			require.NoError(t, err)
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
			require.NoError(t, err)
			defer response.Body.Close()
			// A transport timeout also cancels the request context seen by TimeoutHandler.
			if sender == "untrusted" {
				require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			} else {
				require.Contains(t, []int{http.StatusRequestTimeout, http.StatusServiceUnavailable}, response.StatusCode)
			}
			require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
			require.Empty(t, response.Header.Get("X-Oscar-Scoped-Page-Version"))
		})
	}
}

func TestScopedPageRejectedHTTP2StreamKeepsConnection(t *testing.T) {
	api := newScopedPageTestAPI(t, "12345678901234567890123456789012")
	server := httptest.NewUnstartedServer(api.Register(route.New(), "/am"))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	for i := range 2 {
		reused := false
		ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/am/api/v2/oscar/alerts/scoped-page", strings.NewReader("{}"))
		require.NoError(t, err)
		response, err := client.Do(request)
		require.NoError(t, err)
		require.Equal(t, 2, response.ProtoMajor)
		require.Equal(t, http.StatusUnauthorized, response.StatusCode)
		_, err = io.Copy(io.Discard, response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		if i > 0 {
			require.True(t, reused, "rejected stream must not drain the HTTP/2 connection")
		}
	}
}
