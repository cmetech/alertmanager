// Copyright The Prometheus Authors
// SPDX-License-Identifier: Apache-2.0

package v2

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/require"

	actionclient "github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

const actionBody = `{"version":1,"operation_id":"11111111-1111-4111-8111-111111111111","episode_ref":{"authority_id":"11111111-1111-4111-8111-111111111112","episode_id":"11111111-1111-4111-8111-111111111113","generation":1,"variant_revision":1},"kind":"acknowledge","actor":{"kind":"operator","id":"alice"},"target_scope":[],"target_severity":null,"policy_binding":null}`

type admittedAction struct{ ActionOwner }

func (admittedAction) Execute(_ context.Context, req ActionRequestV1) (ActionResultV1, error) {
	return ActionResultV1{OperationID: req.OperationID, State: "accepted"}, nil
}

func TestOscarActionAssertionComposition(t *testing.T) {
	t.Parallel()
	key := []byte(strings.Repeat("a", 32))
	next := conversionAdmissionGuard(oscarSilenceMutationGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "query unavailable", 503) }), nil), nil)
	guard := actionRoutes(next, map[string][]byte{"operator": key}, admittedAction{}, func() bool { return true })
	for _, tc := range []struct {
		method, path, body, signedBody, grant string
		want                                  int
	}{
		{"POST", actionPath, actionBody, actionBody, "update:alerts:acknowledge", 202},
		{"GET", actionPath, actionBody, actionBody, "update:alerts:acknowledge", 405},
		{"POST", actionPath, actionBody + " ", actionBody, "update:alerts:acknowledge", 401},
		{"POST", actionPath + "/eligibility", actionBody, actionBody, "read:alerts", 401},
		{"POST", actionPath, actionBody, actionBody, "run:alerts:resend", 403},
		{"POST", actionPath, strings.Replace(actionBody, `"version":1`, `"version":2`, 1), strings.Replace(actionBody, `"version":1`, `"version":2`, 1), "update:alerts:acknowledge", 400},
		{"POST", actionPath, strings.Replace(actionBody, `"target_scope":[]`, `"target_scope":[{"receiver_id":"other","action":null,"notifier_id":null}]`, 1), strings.Replace(actionBody, `"target_scope":[]`, `"target_scope":[{"receiver_id":"other","action":null,"notifier_id":null}]`, 1), "update:alerts:acknowledge", 403},
		{"POST", "/api/v2/silences", "", "", "read:alerts", 403},
		{"POST", managedReadPath, "", "", "read:alerts", 401},
		{"GET", "/api/v2/alerts", "", "", "read:alerts", 503},
	} {
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		stamp := strconv.FormatInt(time.Now().Unix(), 10)
		form := strings.Join([]string{"native-action-v1", "POST", actionPath, "operator", "v1", stamp, "YWxpY2U", tc.grant, fmt.Sprintf("%x", sha256.Sum256([]byte(tc.signedBody)))}, "\n")
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(form))
		for k, v := range map[string]string{"Sender": "operator", "Key-Id": "v1", "Time": stamp, "Subject": "YWxpY2U", "Grant": tc.grant, "Signature": fmt.Sprintf("%x", mac.Sum(nil))} {
			r.Header.Set("X-Oscar-Action-"+k, v)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		require.Equal(t, tc.want, w.Code, "%s %s: %s", tc.method, tc.path, w.Body.String())
	}
}

func TestOscarActionCanonicalDigest(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Actor.ID = "Å<&>\u2028\\u2028\u2029"
	req.EpisodeRef.Generation = ^uint64(0)
	digest, err := actionDigest(req)
	require.NoError(t, err)
	require.Equal(t, "5a35e0c79decad6b7bbe2cbbde1c66035cc89c3c19f79cef6da4848f27355e4e", digest)
	for _, bad := range []string{strings.Replace(actionBody, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(actionBody, `"target_severity":null,`, "", 1), strings.Replace(actionBody, `"version":1`, `"Version":1`, 1)} {
		require.False(t, decodeAction([]byte(bad), &ActionRequestV1{}))
	}
}

func TestOscarActionPolicyGrantRejectsSubstitutedRefOrSubset(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	q := policyRecovery{Mode: "transfer", CurrentRef: req.EpisodeRef, TargetKeys: []string{strings.Repeat("a", 64)}}
	q.CurrentRef.VariantRevision++
	body := mustRaw(t, req)
	raw := mustRaw(t, q)
	key := []byte(strings.Repeat("b", 32))
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	subject := base64.RawURLEncoding.EncodeToString([]byte(req.Actor.ID))
	frame := strings.Join([]string{"native-action-v1", "POST", actionPath, "policy", "v1", stamp, subject, "recover:policy", fmt.Sprintf("%x", sha256.Sum256(raw)), fmt.Sprintf("%x", sha256.Sum256(body))}, "\n")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(frame))
	guard := actionRoutes(http.NotFoundHandler(), map[string][]byte{"policy": key}, admittedAction{}, func() bool { return true })
	for _, tc := range []struct {
		change string
		want   int
	}{{"", 202}, {"ref", 401}, {"subset", 401}} {
		r := httptest.NewRequest("POST", actionPath, bytes.NewReader(body))
		altered := q
		if tc.change == "ref" {
			altered.CurrentRef.VariantRevision++
		}
		if tc.change == "subset" {
			altered.TargetKeys = []string{strings.Repeat("c", 64)}
		}
		for n, v := range map[string]string{"Sender": "policy", "Key-Id": "v1", "Time": stamp, "Subject": subject, "Grant": "recover:policy", "Recovery": base64.RawURLEncoding.EncodeToString(mustRaw(t, altered)), "Signature": fmt.Sprintf("%x", mac.Sum(nil))} {
			r.Header.Set("X-Oscar-Action-"+n, v)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		require.Equal(t, tc.want, w.Code, tc.change)
	}
}

func TestPolicyTransferSignedReplayMustMatchOriginalRevision(t *testing.T) {
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.Kind = "resend"
	req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
	req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID}
	req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
	ref := req.EpisodeRef
	ref.VariantRevision++
	digest, err := actionDigest(req)
	require.NoError(t, err)
	childID := "22222222-1111-4111-8111-111111111111"
	o := newNativeActionOwner(req.EpisodeRef.AuthorityID, actionRPCFunc(func(_ context.Context, cmd string, p map[string]any, out any) error {
		require.Equal(t, "lookup", cmd)
		if p["projection"] == "transfer" {
			if p["expected_revision"] != uint64(1) {
				return reconcile
			}
			*out.(*ActionResultV1) = ActionResultV1{OperationID: childID, EpisodeRef: ref, State: "held"}
			return nil
		}
		*out.(**actionIntent) = &actionIntent{Digest: digest, Request: mustRaw(t, req), Result: ActionResultV1{OperationID: req.OperationID, EpisodeRef: req.EpisodeRef}, ReservationSuccessorID: &childID}
		return nil
	}), testActionDispatch{})
	o.recovered = true
	o.lease = actionLease{Epoch: 1, ExpiresAt: time.Now().Add(time.Minute)}
	key := []byte(strings.Repeat("b", 32))
	guard := actionRoutes(http.NotFoundHandler(), map[string][]byte{"policy": key}, o, func() bool { return true })
	body := mustRaw(t, req)
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	subject := base64.RawURLEncoding.EncodeToString([]byte(req.Actor.ID))
	for _, revision := range []uint64{1, 2, 1} {
		raw := mustRaw(t, policyRecovery{Mode: "transfer", CurrentRef: ref, TargetKeys: []string{}, SeverityRevision: revision})
		mac := hmac.New(sha256.New, key)
		fmt.Fprint(mac, strings.Join([]string{"native-action-v1", "POST", actionPath, "policy", "v1", stamp, subject, "recover:policy", fmt.Sprintf("%x", sha256.Sum256(raw)), fmt.Sprintf("%x", sha256.Sum256(body))}, "\n"))
		r := httptest.NewRequest("POST", actionPath, bytes.NewReader(body))
		for name, v := range map[string]string{"Sender": "policy", "Key-Id": "v1", "Time": stamp, "Subject": subject, "Grant": "recover:policy", "Recovery": base64.RawURLEncoding.EncodeToString(raw), "Signature": fmt.Sprintf("%x", mac.Sum(nil))} {
			r.Header.Set("X-Oscar-Action-"+name, v)
		}
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		require.Equal(t, 409, w.Code)
		if revision == 1 {
			require.Contains(t, w.Body.String(), childID)
			_, err := (&actionclient.ExecuteOscarActionReader{}).ReadResponse(actionConflictResponse{body: w.Result().Body}, runtime.JSONConsumer())
			var conflict *actionclient.ExecuteOscarActionConflict
			require.ErrorAs(t, err, &conflict)
			require.NotNil(t, conflict.GetPayload())
			require.Equal(t, childID, fmt.Sprint(conflict.GetPayload().OperationID))
		} else {
			require.NotContains(t, w.Body.String(), childID)
			_, err := (&actionclient.ExecuteOscarActionReader{}).ReadResponse(actionConflictResponse{body: w.Result().Body}, runtime.JSONConsumer())
			var conflict *actionclient.ExecuteOscarActionConflict
			require.ErrorAs(t, err, &conflict)
			require.NotNil(t, conflict.GetPayload())
			require.Equal(t, reconcile.reason, *conflict.GetPayload().Reason)
			require.Empty(t, conflict.GetPayload().OperationID)
		}
	}
}

type actionConflictResponse struct{ body io.ReadCloser }

func (actionConflictResponse) Code() int                  { return http.StatusConflict }
func (actionConflictResponse) Message() string            { return "Conflict" }
func (actionConflictResponse) GetHeader(string) string    { return "" }
func (actionConflictResponse) GetHeaders(string) []string { return nil }
func (r actionConflictResponse) Body() io.ReadCloser      { return r.body }

func TestActionRegistrationRejectsUnsignedBeforeBinding(t *testing.T) {
	api, err := NewAPI(nil, nil, nil, nil, promslog.NewNopLogger(), prometheus.NewRegistry())
	require.NoError(t, err)
	require.NoError(t, api.InstallActionOwner(ActionOwnerConfig{}))
	for _, tc := range []struct{ method, path string }{
		{"POST", actionPath}, {"POST", actionPath + "/eligibility"},
		{"GET", actionPath + "/11111111-1111-4111-8111-111111111111"},
	} {
		w := httptest.NewRecorder()
		api.Handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader("invalid JSON")))
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	}
}

func TestGeneratedActionRequestWire(t *testing.T) {
	t.Parallel()
	var req ActionRequestV1
	require.True(t, decodeAction([]byte(actionBody), &req))
	req.EpisodeRef.Generation = ^uint64(0)
	req.EpisodeRef.VariantRevision = ^uint64(0)
	for _, policy := range []bool{false, true} {
		if policy {
			req.Actor = ActionActor{Kind: "policy", ID: "resend-policy"}
			req.Kind = "resend"
			req.PolicyBinding = &PolicyBinding{BindingID: req.OperationID, RevisionID: req.EpisodeRef.EpisodeID, CancellationGeneration: ^uint64(0)}
			req.TargetScope = []ScopeEntry{{ReceiverID: "ops"}}
		}
		var client models.OscarActionRequest
		require.NoError(t, json.Unmarshal(mustRaw(t, req), &client))
		body, err := json.Marshal(&client)
		require.NoError(t, err)
		var roundTrip ActionRequestV1
		require.True(t, decodeAction(body, &roundTrip))
		require.Equal(t, req, roundTrip)
	}
}
