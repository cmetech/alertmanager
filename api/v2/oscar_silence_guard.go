package v2

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const oscarSilenceMutationHeader = "X-Oscar-Silence-Mutation-Key"

// oscarSilenceMutationGuard protects native silence writes. The caller must
// provide a nonempty key; deployment supplies it through a mounted secret.
func oscarSilenceMutationGuard(next http.Handler, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutation := (r.Method == http.MethodPost && r.URL.Path == "/api/v2/silences") ||
			(r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v2/silence/") && len(r.URL.Path) > len("/api/v2/silence/"))
		if mutation {
			provided := []byte(r.Header.Get(oscarSilenceMutationHeader))
			if len(key) == 0 || subtle.ConstantTimeCompare(provided, key) != 1 {
				http.Error(w, "silence mutation forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
