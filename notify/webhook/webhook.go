// Copyright 2019 Prometheus Team
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

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"regexp"
	"strings"
	"time"

	commoncfg "github.com/prometheus/common/config"

	"github.com/prometheus/alertmanager/alert"
	"github.com/prometheus/alertmanager/notify"
	"github.com/prometheus/alertmanager/template"
)

// Notifier implements a Notifier for generic webhooks.
type Notifier struct {
	conf    *WebhookConfig
	tmpl    *template.Template
	logger  *slog.Logger
	client  *http.Client
	retrier *notify.Retrier
}

// New returns a new Webhook.
func New(conf *WebhookConfig, t *template.Template, l *slog.Logger, httpOpts ...commoncfg.HTTPClientOption) (*Notifier, error) {
	client, err := notify.NewClientWithTracing(*conf.HTTPConfig, "webhook", httpOpts...)
	if err != nil {
		return nil, err
	}
	return &Notifier{
		conf:   conf,
		tmpl:   t,
		logger: l,
		client: client,
		// Webhooks are assumed to respond with 2xx response codes on a successful
		// request and 5xx response codes are assumed to be recoverable.
		retrier: &notify.Retrier{},
	}, nil
}

// Message defines the JSON object send to webhook endpoints.
type managedMember struct {
	alert.ManagedMembership
	Index    int  `json:"index"`
	Eligible bool `json:"eligible"`
}

type managedCallback struct {
	Baseline int64           `json:"baseline"`
	Members  []managedMember `json:"members"`
}

type Message struct {
	NativeDeliveries []alert.NativeDeliveryMember `json:"oscarNativeDeliveries,omitempty"`
	Managed          *managedCallback             `json:"oscarManagedCallback,omitempty"`
	*template.Data

	// The protocol version.
	Version         string `json:"version"`
	GroupKey        string `json:"groupKey"`
	TruncatedAlerts uint64 `json:"truncatedAlerts"`
}

// nativeDeliveryRequest is for the durable native owner. Ordinary Notify never mints action authority.
func (n *Notifier) nativeDeliveryRequest(ctx context.Context, receiver string, msg *Message, sources []*alert.Alert, members []alert.NativeDeliveryMember, key []byte) (*http.Request, error) {
	target := string(n.conf.URL)
	base := "https://alertmanager-middleware:9400"
	if strings.HasPrefix(target, "http://") {
		base = "http://alertmanager-middleware:9400"
	}
	path, canonical := strings.CutPrefix(target, base)
	cfg := n.conf.HTTPConfig
	if !canonical || (path != alert.NativeCallbackPath && path != alert.NativeCallbackPath+"?notifier_type=oscaradmin") ||
		n.conf.URLFile != "" || n.conf.Payload != nil || n.conf.MaxAlerts != 0 || cfg == nil || cfg.FollowRedirects || (strings.HasPrefix(target, "https://") && cfg.TLSConfig.InsecureSkipVerify) ||
		cfg.Authorization == nil || cfg.Authorization.Type != "Bearer" || cfg.Authorization.CredentialsFile == "" {
		return nil, errors.New("native delivery requires the private callback")
	}
	if msg == nil || msg.Data == nil || msg.Receiver != regexp.QuoteMeta(receiver) || msg.TruncatedAlerts != 0 || len(members) == 0 || len(members) != len(msg.Alerts) || len(sources) != len(members) {
		return nil, errors.New("incomplete native delivery batch")
	}
	managed := make(map[int]alert.ManagedMembership)
	if msg.Managed != nil {
		if msg.Managed.Baseline < 0 || len(msg.Managed.Members) == 0 {
			return nil, errors.New("invalid managed callback")
		}
		for _, m := range msg.Managed.Members {
			if _, dup := managed[m.Index]; dup || m.Index < 0 || m.Index >= len(sources) {
				return nil, errors.New("invalid managed callback index")
			}
			managed[m.Index] = m.ManagedMembership
		}
	}
	variants := map[alert.NativeVariant]bool{}
	ids := map[string]bool{}
	for i, member := range members {
		delivery := member.Delivery
		if err := delivery.Validate(receiver); err != nil {
			return nil, err
		}
		a := msg.Alerts[i]
		v := delivery.NativeVariant
		t, err := time.Parse(time.RFC3339Nano, v.StartsAt)
		if err != nil {
			return nil, err
		}
		v.StartsAt = t.UTC().Format(time.RFC3339Nano)
		severity := strings.ToLower(a.Labels["severity"])
		if strings.TrimSpace(severity) == "" {
			severity = "major"
			if a.Status == "resolved" {
				severity = "cleared"
			}
		}
		source := sources[i]
		stamp, enrolled := managed[i]
		if source == nil || enrolled != source.ManagedReceiver || source.Fingerprint().String() != v.Fingerprint || !source.StartsAt.Equal(t) {
			return nil, errors.New("native source binding mismatch")
		}
		logical := a.Status
		if logical != "firing" && logical != "resolved" {
			return nil, errors.New("invalid native transport state")
		}
		if !enrolled && logical == "resolved" && (!source.Resolved() || !source.EndsAt.Equal(a.EndsAt)) {
			return nil, errors.New("ordinary native expiry mismatch")
		}
		if enrolled {
			if stamp != source.ManagedMember || stamp.Generation <= 0 || stamp.Episode == "" || stamp.Event == "" || stamp.Digest == "" {
				return nil, errors.New("managed source membership mismatch")
			}
			switch source.ManagedOperationKind {
			case "clear":
				logical = "resolved"
			case "raise", "update":
				if logical == "resolved" && (!source.Resolved() || !source.EndsAt.Equal(a.EndsAt) || a.EndsAt.Before(source.StartsAt)) {
					return nil, errors.New("managed native expiry mismatch")
				}
			default:
				return nil, errors.New("managed operation kind unavailable")
			}
		}
		if member.Index != i || variants[v] || ids[delivery.DeliveryID] || a.Fingerprint != v.Fingerprint ||
			!a.StartsAt.Equal(t) || delivery.State != logical || delivery.EffectiveSeverity != severity {
			return nil, errors.New("native delivery member mismatch")
		}
		variants[v], ids[delivery.DeliveryID] = true, true
	}
	data := *msg.Data
	data.Receiver = receiver
	signed := *msg
	signed.Data, signed.NativeDeliveries = &data, members
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(&signed); err != nil {
		return nil, err
	}
	headers, err := alert.NativeDeliveryHeaders(buf.Bytes(), receiver, path, key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return req, nil
}

func truncateAlerts(maxAlerts uint64, alerts []*alert.Alert) ([]*alert.Alert, uint64) {
	if maxAlerts != 0 && uint64(len(alerts)) > maxAlerts {
		return alerts[:maxAlerts], uint64(len(alerts)) - maxAlerts
	}

	return alerts, 0
}

// Notify implements the Notifier interface.
func (n *Notifier) Notify(ctx context.Context, alerts ...*alert.Alert) notify.NotifyVerdict {
	alerts, numTruncated := truncateAlerts(n.conf.MaxAlerts, alerts)
	if entry := notify.CurrentProviderEntry(ctx); entry != nil {
		numTruncated += entry.Truncated
	}
	data := notify.GetTemplateData(ctx, n.tmpl, alerts, n.logger)

	var url string
	var tmplErr error
	tmpl := notify.TmplText(n.tmpl, data, &tmplErr)

	if n.conf.URL != "" {
		url = tmpl(string(n.conf.URL))
	} else {
		content, err := os.ReadFile(n.conf.URLFile)
		if err != nil {
			return notify.Unrecoverable(fmt.Errorf("read url_file: %w", err), notify.DefaultReason)
		}
		url = tmpl(strings.TrimSpace(string(content)))
	}

	if tmplErr != nil {
		return notify.Unrecoverable(fmt.Errorf("failed to template webhook URL: %w", tmplErr), notify.DefaultReason)
	}

	if url == "" {
		return notify.Unrecoverable(errors.New("webhook URL is empty after templating"), notify.DefaultReason)
	}

	if notify.CurrentProviderEntry(ctx) != nil && (n.conf.URLFile != "" || strings.Contains(string(n.conf.URL), "{{")) {
		actual, err := neturl.Parse(url)
		if err != nil || (strings.EqualFold(actual.Hostname(), "alertmanager-middleware") || actual.Path == alert.NativeCallbackPath) {
			return notify.Unrecoverable(notify.ErrDestination, notify.ConfigErrorReason)
		}
	}
	if !notify.PreparedHTTPDestination(ctx, n.client, url) {
		return notify.Unrecoverable(notify.ErrDestination, notify.DefaultReason)
	}

	groupKey, err := notify.ExtractGroupKey(ctx)
	if err != nil {
		return notify.Unrecoverable(err, notify.DefaultReason)
	}

	logger := n.logger.With("group_key", groupKey)
	logger.Debug("extracted group key")

	msg := &Message{
		Version:         "4",
		Data:            data,
		GroupKey:        groupKey.String(),
		TruncatedAlerts: numTruncated,
	}

	for index, a := range alerts {
		if !a.ManagedReceiver {
			continue
		}
		previous, known := notify.PreviousNotification(ctx)
		receiver, receiverKnown := notify.ReceiverName(ctx)
		target := string(n.conf.URL)
		const canonical = "https://alertmanager-middleware:9400/api/v1/internal/fingerprint-conversion/alerts"
		allowTarget := target == canonical || target == canonical+"?notifier_type=oscaradmin"
		if entry := notify.CurrentProviderEntry(ctx); entry != nil && len(entry.Members) > 0 {
			httpTarget := strings.Replace(canonical, "https:", "http:", 1)
			allowTarget = allowTarget || target == httpTarget || target == httpTarget+"?notifier_type=oscaradmin"
		}
		if !known || !receiverKnown || a.ManagedEligible == nil || !allowTarget ||
			n.conf.HTTPConfig == nil || n.conf.HTTPConfig.FollowRedirects || (strings.HasPrefix(target, "https://") && n.conf.HTTPConfig.TLSConfig.InsecureSkipVerify) ||
			n.conf.Payload != nil || n.conf.MaxAlerts != 0 {
			return notify.Retry(0, errors.New("managed callback eligibility unavailable"), notify.DefaultReason)
		}
		eligible, err := a.ManagedEligible(ctx, a.ProviderSource(), receiver, groupKey.String())
		if err != nil {
			return notify.Retry(0, err, notify.DefaultReason)
		}
		if msg.Managed == nil {
			msg.Managed = &managedCallback{Baseline: previous}
		}
		msg.Managed.Members = append(msg.Managed.Members, managedMember{a.ManagedMember, index, eligible})
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return notify.Unrecoverable(err, notify.DefaultReason)
	}

	// Override the payload if a custom one is configured.
	if n.conf.Payload != nil {
		buf, err = n.renderPayload(msg)
		if err != nil {
			return notify.Unrecoverable(fmt.Errorf("failed to render custom payload: %w", err), notify.DefaultReason)
		}
	}

	if n.conf.Timeout > 0 {
		postCtx, cancel := context.WithTimeoutCause(ctx, n.conf.Timeout, fmt.Errorf("configured webhook timeout reached (%s)", n.conf.Timeout))
		defer cancel()
		ctx = postCtx
	}

	entry := notify.CurrentProviderEntry(ctx)
	var resp *http.Response
	if entry != nil {
		var req *http.Request
		if len(entry.Members) > 0 {
			sources := make([]*alert.Alert, len(alerts))
			for i, a := range alerts {
				sources[i] = a.ProviderSource()
			}
			receiver, _ := notify.ReceiverName(ctx)
			req, err = n.nativeDeliveryRequest(ctx, receiver, msg, sources, entry.Members, entry.Key)
		} else {
			req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
		}
		if err != nil {
			return notify.Unrecoverable(err, notify.DefaultReason)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", notify.UserAgentHeader)
		resp, err = notify.DoMutation(n.client, req)
		if err != nil {
			return notify.Unrecoverable(notify.RedactURL(err), notify.DefaultReason)
		}
	} else {
		resp, err = notify.PostJSON(ctx, n.client, url, &buf)
	}
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w: %w", err, context.Cause(ctx))
		}
		return notify.Retry(0, notify.RedactURL(err), notify.DefaultReason)
	}
	defer notify.Drain(resp)

	shouldRetry, err := n.retrier.Check(resp.StatusCode, resp.Body)
	if err != nil {
		reason := notify.GetFailureReasonFromStatusCode(resp.StatusCode)
		if entry == nil && shouldRetry {
			return notify.Retry(0, err, reason)
		}
		return notify.Unrecoverable(err, reason)
	}
	return notify.Success()
}

func (n *Notifier) renderPayload(
	data *Message,
) (bytes.Buffer, error) {
	var (
		tmplTextErr  error
		tmplText     = notify.TmplText(n.tmpl, data.Data, &tmplTextErr)
		tmplTextFunc = func(tmpl string) (string, error) {
			return tmplText(tmpl), tmplTextErr
		}
	)
	var err error
	rendered, err := template.DeepCopyWithTemplate(n.conf.Payload, tmplTextFunc)
	if err != nil {
		return bytes.Buffer{}, err
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(rendered); err != nil {
		return bytes.Buffer{}, err
	}
	return buf, nil
}
