package v2

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"path"
	"strings"
)

const (
	oscarInhibitionPrefix = "/api/v2/oscar/inhibition"
	oscarInhibitionHeader = "X-Oscar-Inhibition-Key"
)

func oscarInhibitionGuard(next http.Handler, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		if p == oscarInhibitionPrefix || strings.HasPrefix(p, oscarInhibitionPrefix+"/") {
			if len(key) == 0 || subtle.ConstantTimeCompare([]byte(r.Header.Get(oscarInhibitionHeader)), key) != 1 {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": "forbidden", "message": "Managed inhibition access forbidden."})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
