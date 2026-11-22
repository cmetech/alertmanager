// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	commoncfg "github.com/prometheus/common/config"
	"github.com/stretchr/testify/require"
)

// A real connection exercises the final entry boundary after configured auth.
func TestOscarActionPreparedHTTP(t *testing.T) {
	t.Parallel()
	var calls, permits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "Bearer test-secret", r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/replayed", http.StatusTemporaryRedirect)
		case "/lost":
			_, _ = io.Copy(io.Discard, r.Body)
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			_ = conn.Close()
		}
	}))
	defer sink.Close()
	cfg := commoncfg.DefaultHTTPClientConfig
	cfg.Authorization = &commoncfg.Authorization{Type: "Bearer", Credentials: "test-secret"}
	client, err := NewClientWithTracing(cfg, "test")
	require.NoError(t, err)
	entry := &ProviderEntry{Begin: func() bool { return permits.Add(1) <= 2 }}
	ctx := WithProviderEntry(t.Context(), entry)
	resp, err := PostJSON(ctx, client, sink.URL+"/redirect", strings.NewReader("{}"))
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	Drain(resp)
	_, err = PostText(WithMutationStep(ctx, 1), client, sink.URL+"/lost", nil)
	require.Error(t, err)
	_, err = PostJSON(WithMutationStep(ctx, 2), client, sink.URL+"/denied", strings.NewReader("{}"))
	require.Error(t, err)
	require.EqualValues(t, 2, calls.Load())
}

func TestOscarActionRejectAfterCredentialPreparation(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer sink.Close()
	started, resume := make(chan struct{}), make(chan struct{})
	cfg := commoncfg.DefaultHTTPClientConfig
	cfg.Authorization = &commoncfg.Authorization{Type: "Bearer", CredentialsRef: "test"}
	client, err := NewClientWithTracing(cfg, "test", commoncfg.WithSecretManager(blockingCredential(func(context.Context, string) (string, error) {
		close(started)
		<-resume
		return "test-secret", nil
	})))
	require.NoError(t, err)
	var valid atomic.Bool
	valid.Store(true)
	ctx := WithProviderEntry(t.Context(), &ProviderEntry{Begin: valid.Load})
	done := make(chan error, 1)
	go func() { _, err := PostText(ctx, client, sink.URL, nil); done <- err }()
	<-started
	valid.Store(false)
	close(resume)
	require.Error(t, <-done)
	require.Zero(t, requests.Load())
}

type blockingCredential func(context.Context, string) (string, error)

func (f blockingCredential) Fetch(ctx context.Context, ref string) (string, error) {
	return f(ctx, ref)
}

type opaqueTransport func(*http.Request) (*http.Response, error)

func (f opaqueTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOscarActionOpaqueTransportCannotEnter(t *testing.T) {
	t.Parallel()
	client := &http.Client{Transport: opaqueTransport(func(*http.Request) (*http.Response, error) { t.Fatal("unverified transport invoked"); return nil, nil })}
	_, err := PostText(WithProviderEntry(t.Context(), &ProviderEntry{Begin: func() bool { return true }}), client, "https://example.invalid", nil)
	require.Error(t, err)
}

func TestOscarActionPinnedProviderCredential(t *testing.T) {
	t.Parallel()
	var received string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = r.Header.Get("Authorization") }))
	defer sink.Close()
	tokenFile := filepath.Join(t.TempDir(), "tenant")
	require.NoError(t, os.WriteFile(tokenFile, []byte("first"), 0o600))
	cfg := commoncfg.DefaultHTTPClientConfig
	cfg.Authorization = &commoncfg.Authorization{Type: "Bearer", CredentialsFile: tokenFile}
	client, err := NewClientWithTracing(cfg, "test")
	require.NoError(t, err)
	var binding []string
	ctx := WithProviderEntry(t.Context(), &ProviderEntry{Destination: func(fields ...string) bool { binding = slices.Clone(fields); return true }, Begin: func() bool { return true }})
	require.True(t, PreparedHTTPDestination(ctx, client, sink.URL))
	require.NoError(t, os.WriteFile(tokenFile, []byte("second"), 0o600))
	res, err := PostText(ctx, client, sink.URL, nil)
	require.NoError(t, err)
	Drain(res)
	require.Equal(t, "Bearer first", received)
	require.False(t, PreparedHTTPDestination(WithProviderEntry(t.Context(), &ProviderEntry{Destination: func(fields ...string) bool { return slices.Equal(binding, fields) }}), client, sink.URL))
}

func TestOscarActionConfiguredTLSAndProxy(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Wire-Protocol", r.Proto) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	cfg := commoncfg.DefaultHTTPClientConfig
	cfg.TLSConfig.CA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	client, err := NewClientWithTracing(cfg, "test")
	require.NoError(t, err)
	ctx := WithProviderEntry(t.Context(), &ProviderEntry{Begin: func() bool { return true }})
	res, err := PostJSON(ctx, client, server.URL, strings.NewReader("{}"))
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1", res.Header.Get("Wire-Protocol"))
	Drain(res)
	res, err = PostJSON(t.Context(), client, server.URL, strings.NewReader("{}"))
	require.NoError(t, err)
	require.Equal(t, "HTTP/2.0", res.Header.Get("Wire-Protocol"))
	Drain(res)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Proxy-Recipient", r.URL.Host) }))
	defer proxy.Close()
	u, err := url.Parse(proxy.URL)
	require.NoError(t, err)
	cfg.ProxyURL = commoncfg.URL{URL: u}
	client, err = NewClientWithTracing(cfg, "test-proxy")
	require.NoError(t, err)
	ctx = WithProviderEntry(t.Context(), &ProviderEntry{Begin: func() bool { return true }})
	res, err = PostText(ctx, client, "http://provider.invalid/contact", nil)
	require.NoError(t, err)
	require.Equal(t, "provider.invalid", res.Header.Get("Proxy-Recipient"))
	Drain(res)
}

func TestOscarActionSDKRegeneratesRequestContext(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer sink.Close()
	client, err := NewClientWithTracing(commoncfg.DefaultHTTPClientConfig, "sdk")
	require.NoError(t, err)
	sdk := SDKTransport{Context: WithProviderEntry(t.Context(), &ProviderEntry{Begin: func() bool { return false }}), Client: client}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, sink.URL, nil)
	require.NoError(t, err)
	_, err = sdk.Do(req)
	require.Error(t, err)
	require.Zero(t, calls.Load())
}
