// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/hmac"
	"maps"
	"net/http"
	"slices"
	"sync"

	commoncfg "github.com/prometheus/common/config"
)

// preparedHTTP retains only the most recent credential configuration in the
// notifier's connection pool. Each invocation keeps its own exact transport.
type preparedHTTP struct {
	mu      sync.Mutex
	binding []string
	rt      http.RoundTripper
}

// PreparedHTTPDestination pins addressing credentials that the native transport
// otherwise reloads from files. OAuth client identity comes from the configured
// issuer/client ID. Its issued access tokens can refresh without changing it.
func PreparedHTTPDestination(ctx context.Context, client *http.Client, fields ...string) bool {
	entry := CurrentProviderEntry(ctx)
	if entry == nil {
		return true
	}
	if client == nil {
		return false
	}
	t, ok := client.Transport.(*providerTransport)
	if !ok {
		return false
	}
	// The native CLI has no external secret resolver. A custom embedder's
	// principal-selecting references cannot prove a stable recipient here.
	if t.cfg.Authorization != nil && t.cfg.Authorization.CredentialsRef != "" ||
		t.cfg.BasicAuth != nil && t.cfg.BasicAuth.UsernameRef != "" || t.cfg.TLSConfig.CertRef != "" {
		return false
	}
	cfg, binding, err := pinHTTPFiles(ctx, t.cfg)
	if err != nil {
		return false
	}
	if len(entry.Key) > 0 && (cfg.Authorization == nil || !hmac.Equal([]byte(cfg.Authorization.Credentials), entry.Key)) {
		return false
	}
	if len(entry.Key) > 0 && t.cfg.Authorization != nil {
		file := t.cfg.Authorization.CredentialsFile
		entry.RecheckHTTP = func() bool {
			value, err := commoncfg.NewFileSecret(file).Fetch(ctx)
			return err == nil && hmac.Equal([]byte(value), entry.Key)
		}
	}
	if !PreparedDestination(ctx, append(fields, binding...)...) {
		return false
	}
	if len(binding) == 0 {
		return true
	}
	t.pinned.mu.Lock()
	defer t.pinned.mu.Unlock()
	if t.pinned.rt == nil || !slices.Equal(t.pinned.binding, binding) {
		rt, err := t.build(cfg)
		if err != nil {
			return false
		}
		if c, ok := t.pinned.rt.(interface{ CloseIdleConnections() }); ok {
			c.CloseIdleConnections()
		}
		t.pinned.rt, t.pinned.binding = rt, binding
	}
	entry.http = t.pinned.rt
	return true
}

// HasHTTPIdentityFiles reports whether a fixed endpoint can change its effective
// principal between configuration reloads.
func HasHTTPIdentityFiles(c *commoncfg.HTTPClientConfig) bool {
	if c == nil {
		return false
	}
	if c.Authorization != nil && c.Authorization.CredentialsFile != "" || c.BasicAuth != nil && c.BasicAuth.UsernameFile != "" || c.BearerTokenFile != "" || c.TLSConfig.CertFile != "" {
		return true
	}
	if c.HTTPHeaders != nil {
		for _, h := range c.HTTPHeaders.Headers {
			if len(h.Files) > 0 {
				return true
			}
		}
	}
	return false
}

func pinHTTPFiles(ctx context.Context, c commoncfg.HTTPClientConfig) (commoncfg.HTTPClientConfig, []string, error) {
	var binding []string
	var err error
	read := func(path *string) string {
		if err != nil {
			return ""
		}
		var value string
		value, err = commoncfg.NewFileSecret(*path).Fetch(ctx)
		binding = append(binding, *path, value)
		*path = ""
		return value
	}
	if a := c.Authorization; a != nil && a.CredentialsFile != "" {
		copy := *a
		copy.Credentials = commoncfg.Secret(read(&copy.CredentialsFile))
		c.Authorization = &copy
	}
	if a := c.BasicAuth; a != nil && a.UsernameFile != "" {
		copy := *a
		copy.Username = read(&copy.UsernameFile)
		c.BasicAuth = &copy
	}
	if c.BearerTokenFile != "" {
		c.BearerToken = commoncfg.Secret(read(&c.BearerTokenFile))
	}
	if c.TLSConfig.CertFile != "" {
		c.TLSConfig.Cert = read(&c.TLSConfig.CertFile)
		if c.TLSConfig.KeyFile != "" {
			c.TLSConfig.Key = commoncfg.Secret(read(&c.TLSConfig.KeyFile))
		}
	}
	if c.HTTPHeaders != nil {
		headers := maps.Clone(c.HTTPHeaders.Headers)
		for _, name := range slices.Sorted(maps.Keys(headers)) {
			h := headers[name]
			if len(h.Files) == 0 {
				continue
			}
			h.Secrets = slices.Clone(h.Secrets)
			for _, file := range h.Files {
				h.Secrets = append(h.Secrets, commoncfg.Secret(read(&file)))
			}
			h.Files = nil
			headers[name] = h
		}
		c.HTTPHeaders = &commoncfg.Headers{Headers: headers}
	}
	return c, binding, err
}
