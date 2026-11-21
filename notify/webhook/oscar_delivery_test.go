package webhook

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"testing"

	commoncfg "github.com/prometheus/common/config"
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
	makeRequest := func() ([]byte, error) {
		req, err := notifier.nativeDeliveryRequest(t.Context(), receiver, &msg, members, []byte(fixture.TestKey))
		if err != nil {
			return nil, err
		}
		defer req.Body.Close()
		require.Equal(t, receiver, req.Header.Get("X-Oscar-Native-Receiver"))
		return io.ReadAll(req.Body)
	}
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
