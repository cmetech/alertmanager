// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// AWSProviderClient preserves the resolved SDK transport and its read deadline
// wrapper. Only a concrete AWS builder can supply this guarded transport.
func AWSProviderClient(builder *awshttp.BuildableClient) *http.Client {
	frozen := builder.WithTransportOptions(func(tr *http.Transport) {
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetHTTP1(true)
	}).Freeze()
	c, ok := frozen.(*http.Client)
	if !ok {
		return nil
	}
	rt := c.Transport
	c.Transport = &providerTransport{ordinary: rt, guarded: func() (http.RoundTripper, error) { return rt, nil }}
	return c
}
