package v2

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"

	"github.com/prometheus/common/version"

	"github.com/prometheus/alertmanager/config"
)

// ManagedInhibitionHandler mounts the internal managed API and denies access without a dedicated key.
// Raw JSON handlers keep strict authored-input validation and preserve exact native status snapshots.
func ManagedInhibitionHandler(next http.Handler, c *config.Coordinator, key []byte) http.Handler {
	return oscarInhibitionGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := path.Clean(r.URL.Path)
		expected := ""
		switch p {
		case oscarInhibitionPrefix + "/status":
			expected = http.MethodGet
		case oscarInhibitionPrefix + "/validate":
			expected = http.MethodPost
		case oscarInhibitionPrefix + "/rules":
			expected = http.MethodPut
		default:
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		write := func(code int, value any) { w.WriteHeader(code); _ = json.NewEncoder(w).Encode(value) }
		if r.Method != expected {
			w.Header().Set("Allow", expected)
			write(405, map[string]string{"code": "method_not_allowed", "message": "Unsupported method."})
			return
		}
		if c == nil {
			write(503, map[string]string{"code": "unavailable", "message": "Managed inhibition is not initialized."})
			return
		}
		if expected == http.MethodGet {
			status := c.ManagedInhibitionStatus()
			w.Header().Set("ETag", status.ETag)
			write(200, struct {
				config.ManagedInhibitionStatus
				BuildVersion string         `json:"build_version"`
				Limits       map[string]int `json:"limits"`
				Recording    map[string]any `json:"recording"`
			}{status, version.Version, map[string]int{"max_rules": config.ManagedInhibitionMaxRules, "max_matchers": config.ManagedInhibitionMaxMatchers, "max_equal": config.ManagedInhibitionMaxEqual, "max_body_bytes": config.ManagedInhibitionMaxBodyBytes}, c.ObservationStatus()})
			return
		}
		var body struct {
			Rules *config.ManagedInhibitionRules `json:"rules"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, config.ManagedInhibitionMaxBodyBytes))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&body)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = errors.New("trailing JSON data")
			}
		}
		if err != nil || body.Rules == nil {
			if _, invalid := errors.AsType[*config.ManagedInhibitionValidationError](err); invalid {
				writeManagedError(w, err, nil)
				return
			}
			code := 400
			if _, oversized := errors.AsType[*http.MaxBytesError](err); oversized {
				code = 413
			}
			write(code, map[string]any{"code": "validation_failed", "message": "Expected a bounded JSON object with an explicit rules array.", "errors": []map[string]string{{"field": "rules", "message": "Invalid structured request."}}})
			return
		}
		input := config.ManagedInhibitionSet{Rules: *body.Rules}
		if expected == http.MethodPost {
			compiled, err := config.CompileManagedInhibition(input)
			if err != nil {
				writeManagedError(w, err, nil)
				return
			}
			write(200, map[string]any{"digest": compiled.Digest, "rules": compiled.Definition.Rules})
			return
		}
		status, err := c.ApplyManagedInhibition(r.Header.Get("If-Match"), input)
		w.Header().Set("ETag", status.ETag)
		if err != nil {
			writeManagedError(w, err, &status)
			return
		}
		write(200, status)
	}), key)
}

func writeManagedError(w http.ResponseWriter, err error, status *config.ManagedInhibitionStatus) {
	code := 500
	body := map[string]any{"code": "internal_error", "message": "Managed inhibition operation failed."}
	if validation, ok := errors.AsType[*config.ManagedInhibitionValidationError](err); ok {
		code = 400
		body["code"] = "validation_failed"
		body["message"] = "Managed rules are invalid."
		body["errors"] = []*config.ManagedInhibitionValidationError{validation}
	} else if operation, ok := errors.AsType[*config.ManagedInhibitionError](err); ok {
		body["code"] = operation.Code
		body["message"] = operation.Message
		switch operation.Code {
		case "precondition_required":
			code = 428
		case "precondition_failed":
			code = 412
		case "base_conflict":
			code = 409
		case "activation_failed":
			code = 422
		case "persist_failed", "unavailable":
			code = 503
		}
	}
	if status != nil {
		body["status"] = status
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
