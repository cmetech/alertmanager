// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"encoding/json"
	"net/http"

	"github.com/prometheus/common/model"
)

const ledgerPath = "/api/v2/oscar/ledger"

// ledgerRoute serves the read-only delivery ledger lookup for one provider
// fingerprint, beside the other unauthenticated /api/v2/oscar read routes.
// It never mutates the ledger.
func ledgerRoute(next http.Handler, lookup func(model.Fingerprint) any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != ledgerPath {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		raw := r.URL.Query().Get("fingerprint")
		fp, err := model.ParseFingerprint(raw)
		if err != nil || !nativeFingerprint.MatchString(raw) {
			http.Error(w, "fingerprint must be 16 lowercase hex digits", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"fingerprint": raw, "entries": lookup(fp)})
	})
}
