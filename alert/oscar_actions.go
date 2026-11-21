// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package alert

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/common/model"
)

// NativeCallbackPath is the existing private OSCAR webhook.
const NativeCallbackPath = "/api/v1/internal/fingerprint-conversion/alerts"

var (
	actionID          = regexp.MustCompile("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
	actionFingerprint = regexp.MustCompile("^[0-9a-f]{16}$")
	actionStamp       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)
	actionReceiver    = regexp.MustCompile(`^[!-~]([ -~]*[!-~])?$`)
)

// EpisodeRef identifies the native authority's specific episode and source revision.
type EpisodeRef struct {
	AuthorityID     string `json:"authority_id"`
	EpisodeID       string `json:"episode_id"`
	Generation      uint64 `json:"generation"`
	VariantRevision uint64 `json:"variant_revision"`
}

func (ref EpisodeRef) valid() bool {
	return actionID.MatchString(ref.AuthorityID) && actionID.MatchString(ref.EpisodeID) && ref.Generation > 0 && ref.VariantRevision > 0
}

// NativeVariant retains the original provider fingerprint and source start.
type NativeVariant struct {
	Fingerprint string `json:"fingerprint"`
	StartsAt    string `json:"starts_at"`
}

// TargetScopeEntry selects a receiver, optionally restricted to one notifier action.
type TargetScopeEntry struct {
	ReceiverID string  `json:"receiver_id"`
	NotifierID *string `json:"notifier_id"`
	Action     *string `json:"action"`
}

// NativeDeliveryV1 binds an exact native lifecycle observation to this delivery.
type NativeDeliveryV1 struct {
	Version           int                `json:"version"`
	EpisodeRef        EpisodeRef         `json:"episode_ref"`
	NativeVariant     NativeVariant      `json:"native_variant"`
	LifecycleSeq      uint64             `json:"lifecycle_seq"`
	State             string             `json:"state"`
	ActiveSince       string             `json:"active_since"`
	SourceSeverity    string             `json:"source_severity"`
	EffectiveSeverity string             `json:"effective_severity"`
	DeliveryID        string             `json:"delivery_id"`
	OperationID       *string            `json:"operation_id,omitempty"`
	TargetScope       []TargetScopeEntry `json:"target_scope"`
}

// NativeDeliveryMember binds the signed claim to its zero-based webhook member index.
type NativeDeliveryMember struct {
	Index    int              `json:"index"`
	Delivery NativeDeliveryV1 `json:"delivery"`
}

func firingRank(s string) int {
	switch s {
	case "info":
		return 0
	case "minor":
		return 1
	case "warning":
		return 2
	case "major":
		return 3
	case "critical":
		return 4
	}
	return -1
}

func validTimestamp(s string) bool {
	if !actionStamp.MatchString(s) {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && t.Year() > 0
}

// Validate checks the member against the actual private receiver before signing.
func (d NativeDeliveryV1) Validate(receiver string) error {
	if d.Version != 1 || !d.EpisodeRef.valid() || d.LifecycleSeq == 0 || !actionID.MatchString(d.DeliveryID) ||
		(d.OperationID != nil && !actionID.MatchString(*d.OperationID)) || !actionFingerprint.MatchString(d.NativeVariant.Fingerprint) ||
		!validTimestamp(d.NativeVariant.StartsAt) || !validTimestamp(d.ActiveSince) || d.TargetScope == nil || !actionReceiver.MatchString(receiver) {
		return errors.New("invalid native delivery binding")
	}
	src, eff := firingRank(d.SourceSeverity), firingRank(d.EffectiveSeverity)
	switch d.State {
	case "firing":
		if src < 0 || eff < src {
			return errors.New("invalid firing severity")
		}
	case "resolved":
		if (src < 0 && d.SourceSeverity != "cleared") || (eff < 0 && d.EffectiveSeverity != "cleared") {
			return errors.New("invalid resolved severity")
		}
	default:
		return errors.New("invalid native state")
	}
	seen := map[[3]string]bool{}
	for _, target := range d.TargetScope {
		k := [3]string{target.ReceiverID, "", ""}
		if target.ReceiverID != receiver || (target.NotifierID == nil) != (target.Action == nil) {
			return errors.New("invalid native receiver scope")
		}
		if target.Action != nil {
			k[1], k[2] = *target.NotifierID, *target.Action
			if !actionID.MatchString(k[1]) || (k[2] != "ticket" && k[2] != "notification") {
				return errors.New("invalid native notifier scope")
			}
		}
		if seen[k] {
			return errors.New("duplicate native target")
		}
		seen[k] = true
	}
	return nil
}

// NativeDeliveryHeaders signs already encoded bytes for the exact callback target.
func NativeDeliveryHeaders(body []byte, receiver, requestTarget string, callbackKey []byte) (map[string]string, error) {
	if len(body) == 0 || len(body) > 8<<20 || len(callbackKey) < 32 || len(callbackKey) > 256 || !actionReceiver.MatchString(receiver) ||
		(requestTarget != NativeCallbackPath && requestTarget != NativeCallbackPath+"?notifier_type=oscaradmin") {
		return nil, errors.New("invalid native delivery assertion context")
	}
	const issuer, kid = "alertmanager-native", "callback-v1"
	sum := sha256.Sum256(body)
	frame := strings.Join([]string{"oscar-native-delivery-v1", "POST", requestTarget, issuer, kid, receiver, hex.EncodeToString(sum[:])}, "\n")
	mac := hmac.New(sha256.New, callbackKey)
	mac.Write([]byte(frame))
	return map[string]string{"X-Oscar-Native-Issuer": issuer, "X-Oscar-Native-Key-Id": kid, "X-Oscar-Native-Receiver": receiver,
		"X-Oscar-Native-Signature": hex.EncodeToString(mac.Sum(nil))}, nil
}

// DispatchView carries independent routing labels alongside immutable provider identity.
type DispatchView struct {
	EpisodeRef       EpisodeRef
	NativeVariant    NativeVariant
	EffectiveLabels  model.LabelSet
	SeverityRevision uint64
}

// BuildDispatchView projects severity without modifying the source or its fingerprint.
func BuildDispatchView(source *Alert, ref EpisodeRef, severity string, revision uint64) (DispatchView, error) {
	if source == nil || source.StartsAt.IsZero() || !ref.valid() {
		return DispatchView{}, errors.New("invalid native dispatch source")
	}
	src := strings.ToLower(string(source.Labels["severity"]))
	if strings.TrimSpace(src) == "" {
		src = "major"
	}
	if firingRank(src) < 0 || firingRank(severity) < firingRank(src) {
		return DispatchView{}, errors.New("invalid dispatch severity")
	}
	labels := source.Labels.Clone()
	labels["severity"] = model.LabelValue(severity)
	return DispatchView{ref, NativeVariant{source.Fingerprint().String(), source.StartsAt.UTC().Format(time.RFC3339Nano)}, labels, revision}, nil
}
