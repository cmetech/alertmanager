// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/nflog/nflogpb"
)

// SelectedAction describes one pending journal target of one provider member.
// Invoke must acquire its durable entry claim and check validity before notifying.
type SelectedAction struct {
	Source      *alert.Alert
	Receiver    string
	Integration string
	Index       int
	Invoke      func(context.Context, *Integration, *alert.Alert) NotifyVerdict
}

type selectedActionKey struct{}

// WithSelectedAction passes the selection through the existing suppression and integration stages.
func WithSelectedAction(ctx context.Context, selection SelectedAction) context.Context {
	return context.WithValue(ctx, selectedActionKey{}, selection)
}

func selectedAction(ctx context.Context) (SelectedAction, bool) {
	action, ok := ctx.Value(selectedActionKey{}).(SelectedAction)
	return action, ok
}

func (s SelectedAction) matches(receiver, integration string, index int) bool {
	return s.Receiver == receiver && s.Integration == integration && s.Index == index
}

// ProviderEntry carries one final local entry gate and an optional signed canonical batch.
type ProviderEntry struct {
	// AddressID derives an opaque identity for provider-owned group metadata.
	AddressID func(...string) string

	steps map[int]bool
	http  http.RoundTripper
	// RecheckHTTP verifies a pinned canonical credential before final entry.
	RecheckHTTP func() bool
	Truncated   uint64 // Original webhook members already excluded before terminal contact reservation.
	Begin       func() bool
	// Check verifies preparation without marking an external effect.
	Check func() bool
	// Select records the exact provider input after native filtering.
	Select func([]*alert.Alert)
	// RequireContent excludes generic provider diagnostics from tracked delivery.
	RequireContent bool
	// NoSend marks a conclusive native decision to skip a delivery.
	NoSend bool
	// ActionID is stable across attempts at the same selected logical target.
	ActionID string
	// Destination checks the exact prepared addressing fields before use.
	Destination func(...string) bool
	Members     []alert.NativeDeliveryMember
	Key         []byte
}

type providerEntryKey struct{}

// WithProviderEntry attaches in-process entry authority to a single integration invocation.
func WithProviderEntry(ctx context.Context, entry *ProviderEntry) context.Context {
	return context.WithValue(ctx, providerEntryKey{}, entry)
}

// CurrentProviderEntry returns the entry to check after blocking preparation, immediately before contact.
func CurrentProviderEntry(ctx context.Context) *ProviderEntry {
	entry, _ := ctx.Value(providerEntryKey{}).(*ProviderEntry)
	return entry
}

// OrdinaryBatch selects contacts with durable coverage before the group log is advanced.
type OrdinaryBatch struct {
	Members []*alert.Alert
	// LogMembers reports ordinary acceptances after invocation. An empty slice preserves the group clock.
	LogMembers                 func() ([]*alert.Alert, error)
	Invoke                     func(context.Context, *Integration, []*alert.Alert) NotifyVerdict
	group                      []*alert.Alert
	previous                   *nflogpb.Entry
	groupFiring, groupResolved map[uint64]struct{}
	hash                       func(*alert.Alert) uint64
}

// OrdinaryReader integrates member coverage with the receiver's existing group dedup decision.
type (
	OrdinaryReader    func(context.Context, string, string, int, []*alert.Alert, func([]*alert.Alert) bool) (OrdinaryBatch, error)
	ordinaryReaderKey struct{}
	ordinaryBatchKey  struct{}
)

// WithOrdinaryReader installs the configuration generation's native action reader.
func WithOrdinaryReader(ctx context.Context, reader OrdinaryReader) context.Context {
	return context.WithValue(ctx, ordinaryReaderKey{}, reader)
}

// ErrDestination is returned when a prepared target no longer matches admission.
var ErrDestination = errors.New("native provider destination unavailable")

// PreparedDestination submits the actual addressing fields used by this notifier.
// During planning this is a read-only stop point before provider I/O.
func PreparedDestination(ctx context.Context, fields ...string) bool {
	e := CurrentProviderEntry(ctx)
	return e == nil || e.Destination == nil || e.Destination(fields...)
}

// DestinationDigest binds opaque provider addressing fields to an integration.
func DestinationDigest(key []byte, config string, fields ...string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("oscar-native-recipient-v1"))
	for _, value := range append([]string{config}, fields...) {
		h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(value))))
		h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PreparedDigest renders the configured recipient and stops at its declaration.
// Only the registered native integrations with this pre-I/O declaration use it.
func (i *Integration) PreparedDigest(ctx context.Context, key []byte, config string, members []*alert.Alert) (string, error) {
	var digest string
	entry := &ProviderEntry{AddressID: func(fields ...string) string { return DestinationDigest(key, config, fields...) }, Destination: func(fields ...string) bool {
		digest = DestinationDigest(key, config, fields...)
		return false
	}}
	i.notifier.Notify(WithProviderEntry(ctx, entry), members...)
	if digest == "" {
		return "", ErrDestination
	}
	return digest, nil
}

type mutationStepKey struct{}

// WithMutationStep distinguishes a subsequent configured provider write.
func WithMutationStep(ctx context.Context, step int) context.Context {
	if CurrentProviderEntry(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, mutationStepKey{}, step)
}

func (entry *ProviderEntry) beginStep(ctx context.Context) bool {
	step, _ := ctx.Value(mutationStepKey{}).(int)
	if entry.steps == nil {
		entry.steps = make(map[int]bool)
	}
	if entry.steps[step] {
		return false
	}
	entry.steps[step] = true
	return entry.Begin != nil && entry.Begin()
}

const incompleteContent = "oscarIncompleteContent"

type incompleteContentKey struct{}

// ContentBaseline returns previously acknowledged members while the provider's
// size-limited payload still has an outstanding tail.
func ContentBaseline(ctx context.Context) func(*alert.Alert) bool {
	ack, _ := ctx.Value(incompleteContentKey{}).(func(*alert.Alert) bool)
	return ack
}

// MarkContentIncomplete retains tail progress in the existing group log.
func MarkContentIncomplete(ctx context.Context, incomplete bool) {
	if store, ok := NflogStore(ctx); ok {
		if incomplete {
			store.SetInt(incompleteContent, 1)
		} else {
			store.Delete(incompleteContent)
		}
	}
}
