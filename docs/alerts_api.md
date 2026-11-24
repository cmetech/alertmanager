---
title: Alerts API
sort_rank: 6
nav_icon: sliders
---

**Important**: Prometheus takes care of sending alerts to the Alertmanager.
It is recommended to configure alerting rules in Prometheus based on time
series data instead of sending alerts to the Alerts API, as Prometheus supports
a number of special cases to make sure alerts are delivered even if Alertmanager
crashes or restarts.

You send alerts to Alertmanager via APIv2. The APIv2 is specified as an
OpenAPI specification that can be found [here](https://github.com/prometheus/alertmanager/blob/master/api/v2/openapi.yaml).

APIv1 was deprecated in Alertmanager version 0.16.0 and removed in Alertmanager
version 0.27.0.

To send alerts to APIv2 make a POST request to `api/v2/alerts`. You must set
the `Content-Type` header to `application/json`, and send JSON data containing
an array of alerts.

Here is an example:

```json
[
  {
    "labels": {
      "alertname": "<required_value>",
      "<name>": "<value>",
      ...
    },
    "annotations": {
      "<name>": "<value>",
    },
    "startsAt": "<RFC3339>",
    "endsAt": "<RFC3339>",
    "generatorURL": "<value>"
  },
  ...
]
```

All alerts have labels, annotations, an optional `startsAt` timestamp and an
optional `endsAt` timestamp. All timestamps are expected in the RFC3339 format.

Labels are used to deduplicate identical instances of the same alert, while
annotations are used to include other information about the alert, such as a
summary, description or a URL to a runbook.

The `startsAt` timestamp is the time the alert fired. If omitted, Alertmanager
sets `startsAt` to the current time.

The `endsAt` timestamp is the time the alert should be resolved. If omitted,
Alertmanager sets `endsAt` to the current time + `resolve_timeout`.

The `generatorURL` is a unique URL which links to the source of the alert. For
example, it might link to the firing rule in Prometheus.

## Expectations from clients

Clients are expected to re-send firing alerts to the Alertmanager at regular
intervals until the alert is resolved.

The exact interval depends on a number of variables such as the `endsAt`
timestamp, or if omitted the value of `resolve_timeout`. If the `endsAt`
timestamp is omitted, the Alertmanager will update the existing `endsAt`
timestamp for the alert to the current time + `resolve_timeout`.

Firing alerts are resolved once their `endsAt` timestamp has elapsed.

To ensure resolved notifications are sent for resolved alerts, clients are also
expected to re-send resolved alerts to the Alertmanager for up to 5 minutes
after the alert has resolved. As the Alertmanager is stateless, this ensures
that a resolved notification is sent even if the Alertmanager crashes or is
restarted.

## OSCAR scoped Active page

The middleware reads `POST /api/v2/oscar/alerts/scoped-page` using the native
operator key configured by `--oscar.action-operator-key-file`. Provision this
key independently of action enablement. Resolve the actor's current role
policy server-side on every request. The browser may supply ordinary narrowing
filters but must never select the signed authority.

For example, this actor can see Production alerts for Payments except those
in the restricted datacenter.

```json
{
  "version": 1,
  "scope": {
    "unrestricted": false,
    "allow": [{"logicOperator":"and","items":[
      {"field":"label:environment","operator":"equals","value":"production"},
      {"field":"label:application","operator":"equals","value":"payments"}
    ]}],
    "deny": [{"items":[{"field":"label:datacenter","operator":"equals","value":"restricted"}]}]
  },
  "query": {"page":["1"],"perPage":["10"]}
}
```

Send each of the six `X-Oscar-Read-` headers exactly once. The suffixes are
`Sender` (operator), `Key-Id` (v1), `Time` (canonical decimal Unix seconds),
`Subject` (unpadded base64url of the actor's UTF-8 ID, 1–255 code points),
`Grant` (read:alerts) and `Signature` (hex HMAC-SHA256). Join the following
UTF-8 lines with LF, omitting a final LF. Hash the exact transmitted bytes.
Requests may be at most 60 seconds old or 5 seconds ahead. Use the literal
path, without URL query or content encoding.

```text
native-scoped-page-v1
POST
/api/v2/oscar/alerts/scoped-page
operator
v1
<Time>
<Subject>
read:alerts
<lowercase hex SHA-256 of body>
```

Each allow group represents an independent role match. Within each group
`logicOperator` defaults to `and`, and may also be `or`. Evaluate
`(unrestricted OR any allow group matches) AND no deny group matches`.
Explicit unrestricted requires an empty allow list. A restricted empty allow
list grants zero rows. Reject invalid groups, fields, operators and types.
Each rule addresses one nonblank label name of at most 100 code points with
no surrounding whitespace. Equality takes a string. Membership takes 1–100
strings. Empty strings match only existing labels with an empty value.
Each literal may occupy up to 4096 UTF-8 bytes. Limits are 32 groups and
100 items across both lists, 65536 bytes per compiled group, a 256 KiB
envelope and eight concurrent signed-page requests per native process. The body
read deadline is five seconds or the remaining web request timeout, whichever is
shorter. If the body read times out first, the scoped handler returns HTTP 408.
If the overall web request times out first, the server returns HTTP 503.

Match persisted provider label names and values using the existing grid
Unicode case fold, including Cherokee's uppercase stable form. Preserve
accents, normalization form, trailing whitespace and full label lengths. An
escaped UTF-16 surrogate must be paired. Literal U+FFFD is a valid value.
Each rule is existential over all matching folded names. A missing label
never matches. Duplicate case-equivalent label names may satisfy different
rules independently. OSC-104's Python and SQL implementations must consume
`api/v2/testdata/oscar_scope_parity_v1.json`. SQL needs equivalent case folding,
byte-exact post-fold comparison and an independent EXISTS per rule.
MySQL accent-insensitive or space-padding comparisons can change visibility.

Restricted authority (including unrestricted with denials) withholds identifiable
parents before counting. Producer identity, parent role/event or aggregate
fields suffice even when lineage is incomplete. Children with ordinary
correlation metadata are evaluated independently. This endpoint reads only
native Active data. It applies the existing signed query's narrowing filters
and search to the effective action view, preserving provider fingerprints and
source severity. Counts, timing and severity maps contain authorized rows only.
On a restricted page, a suppressed row keeps its state and lists inhibitor
fingerprints only for sources present on that same authorized page.

Successful responses carry `X-Oscar-Scoped-Page-Version: 1` and the usual
`contract_version: 2` page. All scoped responses specify `Cache-Control: no-store`.
A caller can probe capability with a signed restricted empty allow list.
Require both contracts and fail closed for missing keys, incompatible readers
or errors. OSC-104 owns middleware signing, read-only secret provisioning,
History parity and cross-service integration. OSC-105 owns the browser/native
route gate. Native Go server/client/models and embedded Swagger have been
generated. Elm assets, runtime tests and companion integration remain pending.
