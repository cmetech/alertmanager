package v2

import (
	"crypto/subtle"
	"net/http"
	"path"
	"strings"
)

const oscarSilenceMutationHeader = "X-Oscar-Silence-Mutation-Key"

func silenceMutationAuthorized(r *http.Request, key []byte) bool {
	return len(key) > 0 && subtle.ConstantTimeCompare([]byte(r.Header.Get(oscarSilenceMutationHeader)), key) == 1
}

// oscarSilenceMutationGuard protects native silence writes. The caller must
// provide a nonempty key for writes; an absent key denies all mutations.
func oscarSilenceMutationGuard(next http.Handler, key []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := path.Clean(r.URL.Path)
		mutation := (r.Method == http.MethodPost && cleanPath == "/api/v2/silences") ||
			(r.Method == http.MethodDelete && strings.HasPrefix(cleanPath, "/api/v2/silence/") && len(cleanPath) > len("/api/v2/silence/"))
		if mutation {
			if !silenceMutationAuthorized(r, key) {
				http.Error(w, "silence mutation forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
