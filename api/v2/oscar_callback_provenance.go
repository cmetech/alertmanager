// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import "context"

// CanonicalRoute identifies one structurally matched OSCAR contact on a specific graph.
type CanonicalRoute struct {
	Route    string `json:"route"`
	GroupKey string `json:"group_key"`
	Receiver string `json:"receiver"`
	Digest   string `json:"digest"`
	Path     string `json:"path"`
}

// CallbackProvenance travels only on the authenticated physical entry command.
// A nil Routes slice records unavailable structural scope.
type CallbackProvenance struct {
	Graph          string           `json:"graph"`
	GroupDigest    string           `json:"group_digest"`
	Path           string           `json:"path"`
	SelectedRoute  string           `json:"selected_route"`
	Routes         []CanonicalRoute `json:"routes"`
	SourceSeverity *string          `json:"source_severity"`
}

type callbackProvenanceKey struct{}

// WithCallbackProvenance attaches the sending graph's proof to one physical claim.
func WithCallbackProvenance(ctx context.Context, proof *CallbackProvenance) context.Context {
	if proof == nil {
		return ctx
	}
	return context.WithValue(ctx, callbackProvenanceKey{}, proof)
}
