package v2

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/common/model"
)

const managedAnnotation = "__oscar_managed_lifecycle"

var (
	managedID      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}$`)
	managedHash    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	managedUUID    = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	managedAttempt = regexp.MustCompile(`^[a-f0-9]{32}$`)
	managedOID     = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2,63}$`)
	managedTime    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`)
)

// Flat, exact, bounded fields keep Go and Python on the same single-operation wire format.
func validManagedOperation(raw, actor string, now int64) bool {
	if len(raw) > 4096 {
		return false
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	fields := map[string]string{}
	ints := map[string]int64{}
	for d.More() {
		name, err := d.Token()
		key, ok := name.(string)
		if err != nil || !ok {
			return false
		}
		if _, exists := fields[key]; exists {
			return false
		}
		if _, exists := ints[key]; exists {
			return false
		}
		value, err := d.Token()
		if err != nil {
			return false
		}
		switch key {
		case "protocol", "producer", "owner", "locator", "source_id", "tid", "handler", "revision", "event_id", "source_digest", "binding_digest", "episode_id", "correlation", "started_at", "kind", "clear_at", "attempt":
			s, ok := value.(string)
			if !ok {
				return false
			}
			fields[key] = s
		case "expected_generation", "issued_at", "deadline":
			n, ok := value.(json.Number)
			if !ok {
				return false
			}
			num, err := n.Int64()
			if err != nil {
				return false
			}
			ints[key] = num
		default:
			return false
		}
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	if _, err = d.Token(); err != io.EOF {
		return false
	}
	if len(fields) != 17 || len(ints) != 3 || fields["protocol"] != "managed-receiver-operation-v1" || fields["producer"] != actor || (actor != "webhookreceiver" && actor != "smtpreceiver" && actor != "trapreceiver") {
		return false
	}
	for _, name := range []string{"owner", "source_id", "tid"} {
		if !managedID.MatchString(fields[name]) {
			return false
		}
	}
	if (fields["locator"] != "" && !managedID.MatchString(fields["locator"])) || !(managedID.MatchString(fields["handler"]) || managedOID.MatchString(fields["handler"])) || !managedHash.MatchString(fields["revision"]) || !managedHash.MatchString(fields["binding_digest"]) || !managedHash.MatchString(fields["source_digest"]) || !managedUUID.MatchString(fields["event_id"]) || !managedUUID.MatchString(fields["episode_id"]) || !managedAttempt.MatchString(fields["attempt"]) {
		return false
	}
	correlation := fields["source_id"] + ":" + fields["tid"] + ":" + fields["episode_id"]
	if actor == "webhookreceiver" && fields["locator"] != "" {
		parts := strings.Split(fields["correlation"], ":")
		if len(parts) != 3 || parts[0] != "tl1" || !managedHash.MatchString(parts[1]) || parts[2] != fields["episode_id"] {
			return false
		}
	} else if fields["correlation"] != correlation {
		return false
	}
	issue, end := ints["issued_at"], ints["deadline"]
	if ints["expected_generation"] < 0 || issue <= 0 || end <= issue || end-issue > 10 || issue > now+5 || now >= end {
		return false
	}
	start, err := time.Parse(time.RFC3339Nano, fields["started_at"])
	if err != nil || start.Year() < 1 || start.Nanosecond()%1000000 != 0 || !managedTime.MatchString(fields["started_at"]) {
		return false
	}
	if fields["kind"] == "clear" {
		clear, err := time.Parse(time.RFC3339Nano, fields["clear_at"])
		return err == nil && clear.Nanosecond()%1000000 == 0 && managedTime.MatchString(fields["clear_at"]) && !clear.Before(start)
	}
	return (fields["kind"] == "raise" || fields["kind"] == "update") && fields["clear_at"] == ""
}

func managedPairMatches(raw string, start time.Time, node, source, correlation, kind, resolution string) bool {
	var claims struct {
		Tid, Correlation, Kind string
		Producer, Locator      string
		SourceID               string `json:"source_id"`
		StartedAt              string `json:"started_at"`
		ClearAt                string `json:"clear_at"`
	}
	if json.Unmarshal([]byte(raw), &claims) != nil || claims.Tid != node || claims.Correlation != correlation {
		return false
	}
	if claims.Producer == "webhookreceiver" && claims.Locator != "" && claims.SourceID != source {
		return false
	}
	expected := claims.StartedAt
	if claims.Kind == "clear" {
		if kind != "resolution" || !strings.EqualFold(resolution, "true") {
			return false
		}
		expected = claims.ClearAt
	} else if kind != "problem" || strings.EqualFold(resolution, "true") {
		return false
	}
	instant, err := time.Parse(time.RFC3339Nano, expected)
	return err == nil && start.Equal(instant)
}

func hasManagedFingerprintFields(alert model.Alert) bool {
	for _, fields := range []model.LabelSet{alert.Labels, alert.Annotations} {
		for name := range fields {
			if name == "fingerprint_override" || name == "fingerprint_exclude" || strings.HasPrefix(string(name), "__oscar_fingerprint_") {
				return true
			}
		}
	}
	return false
}
