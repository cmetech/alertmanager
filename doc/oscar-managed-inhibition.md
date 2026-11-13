# OSCAR managed inhibition

OSCAR publishes a complete structured managed rule set to the existing native
configuration coordinator. Configure `--oscar.inhibition-key-file` with a dedicated
service secret (at least 32 bytes, using the same key-file parser as silence writes).
Requests supply `X-Oscar-Inhibition-Key`. Missing credentials deny access. Keep
these endpoints internal; browser requests continue through the owner service.

The overlay lives at `<storage.path>/oscar-inhibition.json` (normally
`/data/oscar-inhibition.json`). The single native reloader owns templates,
receivers, the dispatcher and inhibitor. Managed changes use the last successful
base object; base reloads read the base file and merge the current overlay.
Reserved `oscar-inh-` names in base configuration prevent managed publication.
Base rules remain external by origin, including during startup fallback.

- `GET /api/v2/oscar/inhibition/status` reports runtime identity, ETag, limits,
  canonical active definitions, base identity, and active/durable state separately.
- `POST /api/v2/oscar/inhibition/validate` accepts `{"rules":[...]}` and returns
  native canonical `rules` and `digest` without effects.
- `PUT /api/v2/oscar/inhibition/rules` requires the exact native `If-Match` value
  and replaces the entire managed set. Explicit `{"rules":[]}` removes the set.

A digest describes semantic content. An ETag identifies the runtime transition:
A→B→A does not reuse an ETag, and restart creates a new runtime epoch. On 412,
re-read native state and a fresh SQL desired-set snapshot; do not reuse a stale
candidate with a fresh ETag. The owner service debounces desired edits before
publishing. Native applies are serialized and require one transactional subscriber.

Persistence is temp-write and file fsync, activation, rename, directory fsync.
Activation failure preserves the previous live and durable set. A later disk
failure can leave the desired set live with unknown durability; `persist_failed`
never means nothing activated. Reconcile from status after failures/timeouts.
Same-content retries verify/repair disk without rebuilding runtime components.
Restart uses the last readable durable file; a crash can temporarily roll back
active desired state until SQL reconciliation. Startup overlay errors preserve the
file as diagnostic evidence and run independently valid base configuration with
managed health false. An invalid base still fails startup.

Changed-rule activation follows the normal referenced-template lifecycle. A
broken template or receiver/tracing setup produces `activation_failed`, separate
from field-addressed `validation_failed`. The service logs actionable detail;
API messages omit sensitive configuration details. No template cache is used.

Native inhibition semantics remain unchanged, including resolved targets. A child
that delivered before its parent may have its resolve suppressed and discarded,
leaving History/tickets open without later replay. Source recovery only makes
still-present children eligible for reevaluation. The authorized History → Resend
→ Cleared action requires a reason and closes History independently of delivery;
resend does not run ticket automation or stop a still-firing source. Tickets need
their applicable ticket/provider workflow. Do not add synthetic resolve, parent,
or relationship-based closure behavior.

Relationship recording is opt-in through `--oscar.inhibition-observations`,
`--oscar.inhibition-observation-url`, and
`--oscar.inhibition-observation-key-file`. Use the dedicated evidence secret at
`/run/secrets/inhibition_observation_key`, separate from the control key. The
fixed destination normally is
`http://alertmanager-middleware:9400/api/v1/alerts/internal/inhibition/observations`.
It authenticates with `X-Oscar-Inhibition-Observation-Key` and refuses redirects.
The reserved output name is `oscar-native-inhibition`; authored configurations
cannot replace it. Missing/invalid sink settings degrade recording without
stopping valid base alert processing. Restart after changing the fixed key file.

Only the full-alert notification inhibition evaluation records the exact source
already selected by the native cache. Label-only API reads never record. The
recorder snapshots bounded immutable occurrence data, preserving native
fingerprints and raw starts/ends times. Display maps are not identity inputs.
Unknown starts are explicitly unavailable and bypass repeat suppression.
`ruleOrigin` is `managed` only for coordinator-merged managed definitions; base
rules, including reserved-looking startup fallback names, remain `external`.

Admission uses a recorder-owned, nonwaiting, bounded 65,536-entry cache that
survives inhibitor rebuilds. It refreshes after ten minutes; the shortest supported
OSCAR History retention is one day. Successful local enqueue advances admission,
not delivery or storage acknowledgment. A downstream drop can lose a short-lived
relationship until refresh; no eventual or exhaustive coverage is promised.
At capacity/contention, repeat suppression can be bypassed within capture budgets.
The shared queue has 8,192 slots, output queue 1,024, and residence is at most
30 seconds from the original observation. Batches are at most 100 events/256 KiB,
flushed within 100 ms when capacity is available. Two workers make at most three
attempts with two-second HTTP deadlines and 500 ms exponential backoff. Individual
encoded events over 64 KiB are dropped. Each occurrence map visits at most 32
entries and copies at most 4,096 bytes, with 256-byte keys and 1,024-byte values;
rule snapshots copy at most 20 matchers per side, 20 equal labels, and 4,096
combined matcher/equal bytes. Truncation is explicit. Full rule identity is hashed
once during rule construction, before truncation.

Existing output interests are unioned before any snapshot builder runs; an
inhibition-only sink does not enable alert-created/group/notification builders.
Fixed sink identity, workers, counters and admission survive rule-only and
unrelated recorder-output reloads. Native inhibition and normal delivery never
wait for evidence queues, HTTP or storage.

Internal authenticated status reports actual output initialization/interest,
queue length, admission/suppression/drop/failure counters and receipt/problem/
recovery timestamps. Missing enablement is `not_enabled`; missing/failed sinks
are `degraded`; a quiet initialized producer starts `unknown`. Successful transport
recovery is `recovering` for 30 seconds, then `healthy` only with a receipt within
60 seconds; quiet stale receipts return `unknown`, not a failure. A successful
HTTP receipt does not independently verify alert delivery, and lost evidence is
never declared recovered. Admin visibility/authorization and durable receipt
coalescing belong to the owner service.

OpenAPI server/client/models are generated by `scripts/swagger.sh`, which uses
the locally pinned Go toolchain and does not require Docker. Elm model generation
is a separate `ui/app/Makefile` target using OpenAPI Generator 3.3.4. Do not edit
generated sources manually. The managed endpoints use strict raw handlers before
the generated router so malformed input and safe operation errors have consistent
native shapes.


The additive `gettableAlert.startsAtRaw` field carries the exact UTC
RFC3339Nano occurrence start used by observation identity. Existing `startsAt`
keeps millisecond serialization and native page contract version 2 remains
compatible for older readers. OSCAR's new image pin is required to provide the
raw field for exact sub-millisecond Active Alert relationship discovery; it must
never be reconstructed from the legacy datetime field. Go and Elm contracts are
regenerated together. Status403/503 and validation403/413 now reference the
existing structured error model in generated callers as in actual handlers.

The first-plus-ten-minute-refresh cadence and bounded labels apply to every
existing interested recorder output, not only the fixed OSCAR sink. Existing
consumers no longer receive a fresh inhibition event on every evaluation. Maps
have at most32 entries with the byte limits above; truncation is explicit.
Admission/cache-pressure exceptions can bypass coalescing. Consumers must treat
these as sampled observations, never complete suppression counts or a transition
journal. `TestObservationExistingOutputCadenceCompatibility` asserts this output
contract without restoring expensive per-evaluation snapshots.
