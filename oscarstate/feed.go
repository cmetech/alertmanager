// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package oscarstate implements the bounded, proof-only native alert feed.
// It never acquires a provider lock or performs I/O during publication.
package oscarstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/prometheus/alertmanager/alert"
)

// Cursor identifies a committed position within one source process.
type Cursor struct {
	Epoch    string `json:"epoch"`
	Sequence uint64 `json:"sequence"`
}

// Kind identifies a provider mutation.
type Kind string

const (
	Upsert Kind = "upsert"
	Delete Kind = "delete"
)

// Change owns a copy of the stored native alert for an upsert.
type Change struct {
	Sequence    uint64            `json:"sequence"`
	PublishedAt time.Time         `json:"publishedAt"`
	Kind        Kind              `json:"kind"`
	Fingerprint model.Fingerprint `json:"fingerprint"`
	Alert       *alert.Alert      `json:"alert,omitempty"`
}

// Batch advances Continue only through delivered changes, independently of Head.
type Batch struct {
	Changes     []Change  `json:"changes"`
	Continue    Cursor    `json:"continue"`
	Head        Cursor    `json:"head"`
	HeadAt      time.Time `json:"headAt"`
	HeartbeatAt time.Time `json:"heartbeatAt"`
}

var (
	ErrEpoch  = errors.New("source epoch changed; snapshot required")
	ErrFuture = errors.New("cursor is ahead of source")
	ErrGap    = errors.New("changes evicted; snapshot required")
)

// Feed retains a fixed number of changes. Lock order is provider then feed.
type Feed struct {
	mu                  sync.Mutex
	ring                []Change
	head                Cursor
	headAt, heartbeatAt time.Time
}

// NewFeed creates a ring. Empty epoch generates a random process epoch; explicit
// epochs support deterministic tests and must never be reused across restarts.
func NewFeed(capacity int, epoch string) *Feed {
	if capacity <= 0 {
		panic("feed capacity must be positive")
	}
	if epoch == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		epoch = hex.EncodeToString(b[:])
	}
	return &Feed{ring: make([]Change, capacity), head: Cursor{Epoch: epoch}}
}

// CopyAlert returns an independently owned native alert, preserving its fingerprint.
func CopyAlert(a *alert.Alert) *alert.Alert {
	if a == nil {
		return nil
	}
	c := *a
	c.Labels = a.Labels.Clone()
	c.Annotations = a.Annotations.Clone()
	return &c
}

// Publish assigns time and sequence and evicts the oldest entry in O(1).
func (f *Feed) Publish(c Change) {
	c.Alert = CopyAlert(c.Alert)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.head.Sequence++
	c.Sequence = f.head.Sequence
	c.PublishedAt = time.Now().UTC()
	f.ring[(c.Sequence-1)%uint64(len(f.ring))] = c
	f.headAt = c.PublishedAt
}

// Cursor returns the current source head.
func (f *Feed) Cursor() Cursor { f.mu.Lock(); defer f.mu.Unlock(); return f.head }

// Heartbeat records provider-confirmed contact, without creating a change.
func (f *Feed) Heartbeat(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.After(f.heartbeatAt) {
		f.heartbeatAt = now.UTC()
	}
}

// Read returns at most limit changes, each with independent payload ownership.
func (f *Feed) Read(after Cursor, limit int) (Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := Batch{Continue: after, Head: f.head, HeadAt: f.headAt, HeartbeatAt: f.heartbeatAt, Changes: []Change{}}
	if after.Epoch != f.head.Epoch {
		return b, ErrEpoch
	}
	if after.Sequence > f.head.Sequence {
		return b, ErrFuture
	}
	if f.head.Sequence-after.Sequence > uint64(len(f.ring)) {
		return b, ErrGap
	}
	if limit <= 0 {
		return b, errors.New("limit must be positive")
	}
	count := min(uint64(limit), f.head.Sequence-after.Sequence)
	for i := range count {
		c := f.ring[(after.Sequence+i)%uint64(len(f.ring))]
		c.Alert = CopyAlert(c.Alert)
		b.Changes = append(b.Changes, c)
		b.Continue.Sequence = c.Sequence
	}
	return b, nil
}
