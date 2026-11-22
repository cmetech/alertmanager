// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"

	commoncfg "github.com/prometheus/common/config"
)

var errProviderEntry = errors.New("native provider entry unavailable")

type mutationKey struct{}

// providerTransport preserves the configured ordinary client. Guarded HTTP/1
// requests have an exclusive connection from GotConn until completion. This
// allows rejecting a mutation after auth, proxy and TLS setup by closing that
// connection before net/http hands the request to its writer. HTTP/2 multiplexes
// unrelated streams on that connection and cannot provide this abort boundary.
type providerTransport struct {
	ordinary http.RoundTripper
	raw      http.RoundTripper
	cfg      commoncfg.HTTPClientConfig
	build    func(commoncfg.HTTPClientConfig) (http.RoundTripper, error)
	pinned   preparedHTTP
	guarded  func() (http.RoundTripper, error)
}

func newProviderTransport(raw, ordinary http.RoundTripper, cfg commoncfg.HTTPClientConfig, name string, opts []commoncfg.HTTPClientOption) *providerTransport {
	build := func(c commoncfg.HTTPClientConfig) (http.RoundTripper, error) {
		options := append([]commoncfg.HTTPClientOption(nil), opts...)
		return commoncfg.NewRoundTripperFromConfig(c, name, append(options, commoncfg.WithHTTP2Disabled())...)
	}
	return &providerTransport{ordinary: ordinary, raw: raw, cfg: cfg, build: build, guarded: sync.OnceValues(func() (http.RoundTripper, error) { return build(cfg) })}
}

func (t *providerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if entry := CurrentProviderEntry(req.Context()); entry != nil && entry.http != nil {
		return entry.http.RoundTrip(req)
	}
	if _, guarded := req.Context().Value(mutationKey{}).(bool); guarded {
		rt, err := t.guarded()
		if err != nil {
			return nil, errProviderEntry
		}
		return rt.RoundTrip(req)
	}
	if CurrentProviderEntry(req.Context()) != nil && t.raw != nil {
		return t.raw.RoundTrip(req)
	}
	return t.ordinary.RoundTrip(req)
}

// DoMutation submits one configured effect. Each distinct native provider
// substep calls this once; redirects and transport replay cannot grant entry.
func DoMutation(client *http.Client, req *http.Request) (*http.Response, error) {
	if client == nil {
		return nil, errProviderEntry
	}
	entry := CurrentProviderEntry(req.Context())
	if entry == nil {
		return client.Do(req)
	}
	if _, ok := client.Transport.(*providerTransport); !ok {
		return nil, errProviderEntry
	}
	if entry.Begin == nil || req.Context().Err() != nil {
		return nil, errProviderEntry
	}
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(), mutationKey{}, true))
	var used atomic.Bool
	trace := &httptrace.ClientTrace{GotConn: func(conn httptrace.GotConnInfo) {
		if !used.CompareAndSwap(false, true) || ctx.Err() != nil || !entry.beginStep(ctx) || ctx.Err() != nil {
			cancel()
			_ = conn.Conn.Close()
		}
	}}
	req = req.Clone(httptrace.WithClientTrace(ctx, trace))
	req.GetBody = nil
	single := *client
	single.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := single.Do(req)
	if err != nil {
		cancel()
		return nil, errProviderEntry
	}
	// Canceling before the notifier reads the provider acknowledgement would
	// turn a successful Slack or Jira write into an ambiguous result.
	res.Body = &providerResponse{ReadCloser: res.Body, cancel: cancel}
	return res, nil
}

type providerResponse struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *providerResponse) Close() error {
	defer r.cancel()
	return r.ReadCloser.Close()
}

// SDKTransport adapts a provider SDK's freshly created request to the native
// invocation context. A guarded publish/send gets exactly one SDK submission.
type SDKTransport struct {
	Context context.Context
	Client  *http.Client
	used    atomic.Bool
}

func (s *SDKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(s.Context)
	stop := context.AfterFunc(req.Context(), cancel)
	closeContext := func() { stop(); cancel() }
	res, err := s.Do(req.WithContext(ctx))
	if err != nil {
		closeContext()
		return nil, err
	}
	res.Body = &providerResponse{ReadCloser: res.Body, cancel: closeContext}
	return res, nil
}

// Do implements the AWS HTTPClient contract at the final signed request.
func (s *SDKTransport) Do(req *http.Request) (*http.Response, error) {
	if s.Client == nil {
		return nil, errProviderEntry
	}
	if entry := CurrentProviderEntry(s.Context); entry != nil {
		if s.Context.Err() != nil || !s.used.CompareAndSwap(false, true) {
			return nil, errProviderEntry
		}
		// SDKs can create fresh request contexts. Carry the invocation's
		// authority onto the final signed request, preserving SDK deadlines.
		req = req.WithContext(WithProviderEntry(req.Context(), entry))
	}
	return DoMutation(s.Client, req)
}
