package v2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/alertmanager/config"
	amcommoncfg "github.com/prometheus/alertmanager/config/common"
	"github.com/prometheus/alertmanager/notify/webhook"
	commoncfg "github.com/prometheus/common/config"
	"github.com/stretchr/testify/require"
)

func managedTestCertificate(t *testing.T, host string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, ca
}

func managedTestClient(t *testing.T, scheme, ca string) *managedClient {
	t.Helper()
	key := filepath.Join(t.TempDir(), "owner.key")
	require.NoError(t, os.WriteFile(key, []byte(strings.Repeat("o", 48)), 0600))
	client, err := newManagedClient(scheme, ca, key)
	require.NoError(t, err)
	t.Cleanup(client.http.CloseIdleConnections)
	return client
}

func managedTestDial(t *testing.T, client *managedClient, server *httptest.Server) {
	t.Helper()
	client.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		require.Equal(t, "alertmanager-middleware:9400", address)
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, server.Listener.Addr().String())
	}
}

func TestManagedOwnerConfiguredTransport(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			requests := make(chan *http.Request, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests <- r.Clone(context.Background())
				io.WriteString(w, `{"contract":"managed-episode-owner-v1"}`)
			}))
			ca := filepath.Join(t.TempDir(), "not-required-for-http.pem")
			if scheme == "https" {
				cert, file := managedTestCertificate(t, "alertmanager-middleware")
				ca = file
				server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			client := managedTestClient(t, scheme, ca)
			managedTestDial(t, client, server)
			var result map[string]string
			require.NoError(t, client.call(t.Context(), "capability", map[string]any{}, &result))
			require.Equal(t, managedContract, result["contract"])
			request := <-requests
			require.Equal(t, http.MethodPost, request.Method)
			require.Equal(t, "alertmanager-middleware:9400", request.Host)
			require.Equal(t, "/api/v1/internal/managed-receiver/capability", request.URL.Path)
			require.Equal(t, "Bearer "+strings.Repeat("o", 48), request.Header.Get("Authorization"))
		})
	}
}

func TestManagedOwnerHTTPSRejectsInvalidPeers(t *testing.T) {
	t.Parallel()
	for _, wrongHost := range []bool{false, true} {
		t.Run(map[bool]string{false: "untrusted-ca", true: "wrong-hostname"}[wrongHost], func(t *testing.T) {
			t.Parallel()
			host := "alertmanager-middleware"
			if wrongHost {
				host = "another-service"
			}
			cert, ca := managedTestCertificate(t, host)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unverified peer received an authenticated request")
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			if !wrongHost {
				_, ca = managedTestCertificate(t, host)
			}
			client := managedTestClient(t, "https", ca)
			managedTestDial(t, client, server)
			var result any
			require.Error(t, client.call(t.Context(), "capability", map[string]any{}, &result))
		})
	}
}

func TestManagedOwnerRejectsRedirectAndUnknownScheme(t *testing.T) {
	t.Parallel()
	client := managedTestClient(t, "http", "")
	calls := 0
	client.http.Transport = ownerTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": {"https://unrelated.invalid/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	var result any
	require.Error(t, client.call(t.Context(), "capability", map[string]any{}, &result))
	require.Equal(t, 1, calls)
	_, err := newManagedClient("ftp", "", "")
	require.ErrorContains(t, err, "invalid managed owner scheme")
	_, err = newManagedClient("https", "", "")
	require.Error(t, err, "HTTPS cannot silently fall back when its CA is missing")
}

func TestManagedCallbackUsesOwnerTransport(t *testing.T) {
	t.Parallel()
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			key := []byte(strings.Repeat("c", 48))
			file := filepath.Join(t.TempDir(), "callback.key")
			require.NoError(t, os.WriteFile(file, key, 0600))
			for _, change := range []string{"none", "scheme", "host", "path", "redirect", "credential", "insecure-tls", "other-ca"} {
				cfg := &webhook.WebhookConfig{URL: amcommoncfg.SecretTemplateURL(scheme + "://alertmanager-middleware:9400/api/v1/internal/fingerprint-conversion/alerts"),
					HTTPConfig: &commoncfg.HTTPClientConfig{Authorization: &commoncfg.Authorization{Type: "Bearer", CredentialsFile: file}, TLSConfig: commoncfg.TLSConfig{CAFile: "owner-ca.pem"}}}
				cfg.VSendResolved = true
				api := &API{conversionCallbackKey: key, managedOwner: &managedOwner{client: &managedClient{scheme: scheme, caFile: "owner-ca.pem"}},
					alertmanagerConfig: &config.Config{Receivers: []config.Receiver{{Name: "oscar", WebhookConfigs: []*webhook.WebhookConfig{cfg}}}}}
				switch change {
				case "scheme":
					cfg.URL = amcommoncfg.SecretTemplateURL(strings.Replace(string(cfg.URL), scheme+":", map[string]string{"http": "https:", "https": "http:"}[scheme], 1))
				case "host":
					cfg.URL = amcommoncfg.SecretTemplateURL(strings.Replace(string(cfg.URL), "alertmanager-middleware", "another-service", 1))
				case "path":
					cfg.URL += "/extra"
				case "redirect":
					cfg.HTTPConfig.FollowRedirects = true
				case "credential":
					cfg.HTTPConfig.Authorization.CredentialsFile = "missing-key"
				case "insecure-tls":
					cfg.HTTPConfig.TLSConfig.InsecureSkipVerify = true
				case "other-ca":
					cfg.HTTPConfig.TLSConfig.CAFile = "another-ca.pem"
				}
				want := change == "none" || (scheme == "http" && (change == "insecure-tls" || change == "other-ca"))
				require.Equal(t, want, api.conversionCallbackReady(), change)
			}
		})
	}
}

func TestOscarActionDirectReadinessPreservesConversionGate(t *testing.T) {
	t.Parallel()
	api := &API{alertmanagerConfig: &config.Config{Receivers: []config.Receiver{{Name: "direct", WebhookConfigs: []*webhook.WebhookConfig{{URL: "https://receiver.example/alerts"}}}}}}
	require.True(t, api.callbacksReadyFor(&managedClient{scheme: "https"}, true))
	require.False(t, api.conversionCallbackReady())
	api.alertmanagerConfig.Receivers[0].WebhookConfigs[0].URL = "https://alertmanager-middleware:9400/api/v1/internal/fingerprint-conversion/alerts"
	require.False(t, api.callbacksReadyFor(&managedClient{scheme: "https"}, true))
}
