// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"
)

func TestLedgerRouteReadOnlyLookup(t *testing.T) {
	t.Parallel()
	var asked []model.Fingerprint
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := ledgerRoute(next, func(fp model.Fingerprint) any {
		asked = append(asked, fp)
		return []map[string]any{{"receiver": "oscar"}}
	})
	call := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
		return w
	}
	w := call("GET", "/api/v2/oscar/ledger?fingerprint=0123456789abcdef")
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	var body struct {
		Fingerprint string           `json:"fingerprint"`
		Entries     []map[string]any `json:"entries"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "0123456789abcdef", body.Fingerprint)
	require.Len(t, body.Entries, 1)
	require.Equal(t, []model.Fingerprint{0x0123456789abcdef}, asked)

	require.Equal(t, http.StatusMethodNotAllowed, call("POST", "/api/v2/oscar/ledger?fingerprint=0123456789abcdef").Code, "read-only")
	for _, bad := range []string{"", "xyz", "0123456789ABCDEF", "123"} {
		require.Equal(t, http.StatusBadRequest, call("GET", "/api/v2/oscar/ledger?fingerprint="+bad).Code, bad)
	}
	require.Equal(t, http.StatusTeapot, call("GET", "/api/v2/oscar/alerts/page").Code, "other routes pass through")
	require.Len(t, asked, 1)
}
