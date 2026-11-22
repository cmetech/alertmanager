package webhook

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"testing"
	"time"

	commoncfg "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/alertmanager/alert"
	amcommoncfg "github.com/prometheus/alertmanager/config/common"
	"github.com/prometheus/alertmanager/template"
)

func TestOscarActionPrivateWebhook(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/v2/testdata/oscar_actions_v1.json")
	require.NoError(t, err)
	var fixture struct {
		Body    string
		TestKey string `json:"test_key"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixture))
	msg := Message{Data: &template.Data{}}
	require.NoError(t, json.Unmarshal([]byte(fixture.Body), &msg))
	receiver := "oscar.ops[primary]"
	msg.Receiver = regexp.QuoteMeta(receiver)
	members := msg.NativeDeliveries
	msg.NativeDeliveries = nil
	members[1].Delivery.TargetScope[0].ReceiverID = receiver
	conf := &WebhookConfig{URL: "https://alertmanager-middleware:9400" + alert.NativeCallbackPath,
		HTTPConfig: &commoncfg.HTTPClientConfig{Authorization: &commoncfg.Authorization{Type: "Bearer", CredentialsFile: "/run/secrets/native-callback"}}}
	notifier := &Notifier{conf: conf}
	sources := make([]*alert.Alert, len(msg.Alerts))
	for i, a := range msg.Alerts {
		sources[i] = alert.New(model.Alert{Labels: model.LabelSet{"severity": "major", "alertname": "disk"}, StartsAt: a.StartsAt}, a.StartsAt, false)
		msg.Alerts[i].Fingerprint = sources[i].Fingerprint().String()
		members[i].Delivery.NativeVariant.Fingerprint = msg.Alerts[i].Fingerprint
	}
	makeRequest := func() ([]byte, error) {
		req, err := notifier.nativeDeliveryRequest(t.Context(), receiver, &msg, sources, members, []byte(fixture.TestKey))
		if err != nil {
			return nil, err
		}
		defer req.Body.Close()
		require.Equal(t, receiver, req.Header.Get("X-Oscar-Native-Receiver"))
		return io.ReadAll(req.Body)
	}
	// Stock Compose selects a verified CA for HTTPS and carries the TLS-only
	// skip flag on its exact plain-HTTP callback.
	conf.HTTPConfig.TLSConfig.CAFile = "/home/ssl/ca.pem"
	conf.HTTPConfig.TLSConfig.InsecureSkipVerify = true
	_, err = makeRequest()
	require.Error(t, err)
	conf.URL = "http://alertmanager-middleware:9400" + alert.NativeCallbackPath
	conf.HTTPConfig.TLSConfig.CAFile = ""
	_, err = makeRequest()
	require.NoError(t, err)
	conf.URL = "https://alertmanager-middleware:9400" + alert.NativeCallbackPath
	conf.HTTPConfig.TLSConfig.CAFile = "/home/ssl/ca.pem"
	conf.HTTPConfig.TLSConfig.InsecureSkipVerify = false
	wire, err := makeRequest()
	require.NoError(t, err)
	var signed Message
	require.NoError(t, json.Unmarshal(wire, &signed))
	require.Equal(t, receiver, signed.Receiver)
	require.Equal(t, regexp.QuoteMeta(receiver), msg.Receiver)
	require.Nil(t, msg.NativeDeliveries)
	conf.URL += "?notifier_type=oscaradmin"
	_, err = makeRequest()
	require.NoError(t, err)
	for _, bad := range []string{"https://unrelated" + alert.NativeCallbackPath,
		"https://alertmanager-middleware:9400" + alert.NativeCallbackPath + "?notifier_type=oscaradmin&notifier_type=oscaradmin"} {
		conf.URL = amcommoncfg.SecretTemplateURL(bad)
		_, err = makeRequest()
		require.Error(t, err)
	}
	conf.URL = "https://alertmanager-middleware:9400" + alert.NativeCallbackPath
	members[1].Index = 0
	_, err = makeRequest()
	require.Error(t, err)
}

func TestOscarActionManagedClearWebhook(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/v2/testdata/oscar_actions_managed_clear_v1.json")
	require.NoError(t, err)
	var vector struct {
		Body    string
		TestKey string `json:"test_key"`
	}
	require.NoError(t, json.Unmarshal(raw, &vector))
	msg := Message{Data: &template.Data{}}
	require.NoError(t, json.Unmarshal([]byte(vector.Body), &msg))
	a := msg.Alerts[0]
	labels := model.LabelSet{}
	for k, v := range a.Labels {
		labels[model.LabelName(k)] = model.LabelValue(v)
	}
	src := alert.New(model.Alert{Labels: labels, StartsAt: a.StartsAt}, a.StartsAt, false)
	require.Equal(t, a.Fingerprint, src.Fingerprint().String())
	src.ManagedReceiver, src.ManagedOperationKind = true, "clear"
	src.ManagedMember = msg.Managed.Members[0].ManagedMembership
	notifier := Notifier{conf: &WebhookConfig{URL: "https://alertmanager-middleware:9400" + alert.NativeCallbackPath, HTTPConfig: &commoncfg.HTTPClientConfig{
		Authorization: &commoncfg.Authorization{Type: "Bearer", CredentialsFile: "/run/secrets/native-callback"}}}}
	build := func() error {
		req, err := notifier.nativeDeliveryRequest(t.Context(), msg.Receiver, &msg, []*alert.Alert{src}, msg.NativeDeliveries, []byte(vector.TestKey))
		if err == nil {
			req.Body.Close()
		}
		return err
	}
	require.NoError(t, build())
	msg.NativeDeliveries[0].Delivery.State = "firing"
	msg.NativeDeliveries[0].Delivery.SourceSeverity = "major"
	msg.NativeDeliveries[0].Delivery.EffectiveSeverity = "major"
	msg.Alerts[0].Labels["severity"] = "major"
	require.Error(t, build())
	msg.NativeDeliveries[0].Delivery.State = "resolved"
	src.ManagedOperationKind = "update"
	require.Error(t, build())
	src.ManagedOperationKind = "clear"
	msg.Managed.Members[0].Generation++
	require.Error(t, build())
	msg.Managed = nil
	src.ManagedReceiver = false
	require.Error(t, build())
}

func TestOscarActionManagedExpiryRequiresCurrentProviderEnd(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../api/v2/testdata/oscar_actions_managed_clear_v1.json")
	require.NoError(t, err)
	var vector struct {
		Body    string
		TestKey string `json:"test_key"`
	}
	require.NoError(t, json.Unmarshal(raw, &vector))
	msg := Message{Data: &template.Data{}}
	require.NoError(t, json.Unmarshal([]byte(vector.Body), &msg))
	end := time.Now().UTC().Add(-time.Minute)
	start := end.Add(-time.Hour)
	labels := model.LabelSet{"severity": "major"}
	src := alert.New(model.Alert{Labels: labels, StartsAt: start, EndsAt: end}, start, true)
	src.ManagedReceiver = true
	src.ManagedMember = msg.Managed.Members[0].ManagedMembership
	src.ManagedOperationKind = "raise"
	rendered := &msg.Alerts[0]
	rendered.Status, rendered.StartsAt, rendered.EndsAt, rendered.Fingerprint = "resolved", start, end, src.Fingerprint().String()
	rendered.Labels = template.KV{"severity": "major"}
	proof := &msg.NativeDeliveries[0].Delivery
	proof.ActiveSince, proof.SourceSeverity, proof.EffectiveSeverity = start.Format(time.RFC3339Nano), "major", "major"
	proof.NativeVariant = alert.NativeVariant{Fingerprint: rendered.Fingerprint, StartsAt: start.Format(time.RFC3339Nano)}
	notifier := Notifier{conf: &WebhookConfig{URL: "https://alertmanager-middleware:9400" + alert.NativeCallbackPath, HTTPConfig: &commoncfg.HTTPClientConfig{
		Authorization: &commoncfg.Authorization{Type: "Bearer", CredentialsFile: "/run/secrets/native-callback"}}}}
	build := func() error {
		req, err := notifier.nativeDeliveryRequest(t.Context(), msg.Receiver, &msg, []*alert.Alert{src}, msg.NativeDeliveries, []byte(vector.TestKey))
		if err == nil {
			req.Body.Close()
		}
		return err
	}
	for _, kind := range []string{"raise", "update"} {
		src.ManagedOperationKind = kind
		src.EndsAt, rendered.EndsAt = end, end
		require.NoError(t, build())
		src.EndsAt = end.Add(time.Nanosecond)
		require.Error(t, build())
		rendered.EndsAt = src.EndsAt
		require.NoError(t, build())
		src.EndsAt = time.Now().Add(time.Hour)
		rendered.EndsAt = src.EndsAt
		require.Error(t, build())
		src.EndsAt, rendered.EndsAt = time.Time{}, time.Time{}
		require.Error(t, build())
	}
}
