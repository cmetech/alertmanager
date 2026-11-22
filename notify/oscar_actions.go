// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"

	"github.com/prometheus/alertmanager/alert"
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
	Truncated uint64 // Original webhook members already excluded before terminal contact reservation.
	Begin     func() bool
	Members   []alert.NativeDeliveryMember
	Key       []byte
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
	Members    []*alert.Alert
	WriteGroup bool
	AllowLog   func() bool // A completely covered firing batch leaves the previous group clock in place.
	Held       error
	Invoke     func(context.Context, *Integration, []*alert.Alert) NotifyVerdict
}

// OrdinaryReader integrates member coverage with the receiver's existing group dedup decision.
type OrdinaryReader func(context.Context, string, string, int, []*alert.Alert, func([]*alert.Alert) bool) (OrdinaryBatch, error)
type ordinaryReaderKey struct{}
type ordinaryBatchKey struct{}

// WithOrdinaryReader installs the configuration generation's native action reader.
func WithOrdinaryReader(ctx context.Context, reader OrdinaryReader) context.Context {
	return context.WithValue(ctx, ordinaryReaderKey{}, reader)
}
