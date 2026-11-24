# OSC-117 native scoped Active page

Approved dependency of OSC-104 Task 4. Base b3cf31d9db656f34c442e321cd06f71a551d65c7. Independent design reviews are recorded on OSC-104, latest round 3 READY with integration gates. Corey authorized implementation after review.

## Global constraints

Preserve native-only Active paging, actionView and ProviderSource identity; no History fallback. Existing flat filterModel syntax remains unchanged. Authorization must precede count/page/timing metadata. Empty allowed groups deny, explicit unrestricted distinct; invalid nonempty policy must reject rather than broaden. Preserve role boundaries and effective denies. Restricted parents without complete safe lineage are withheld. Ordinary page/user filters only narrow authority. Existing unrestricted behavior remains compatible.

Source-only execution: write tests before implementation; no builds, runtime tests, services, containers, CI, deployments or merge. Generated files must not be hand-edited. Formatting and offline structural checks are allowed. Report unrun validation honestly. Keep scope within native repository; Python caller/deployment provisioning and UI native gate are linked OSC-104/105 prerequisites for activation.

## Task 1: Implement protected native paging contract

Read native AGENTS.md. Implement signed POST /api/v2/oscar/alerts/scoped-page using existing signing/strict-decode patterns with distinct read domain, actor/method/path/time/full body binding. Browser-supplied authority never suffices. Operator-only key verification must work independently of mutation-action enablement; do not enable actions for reads. Reuse existing options/key-file configuration where possible. Reject missing, altered, duplicate, expired, malformed or cross-audience assertions and unknown/oversized envelopes. Bound body, policy, concurrency and filter work.

Carry bounded groups of the existing flat filter models (label:<key>, equals/isAnyOf), combine role allows as union and effective denials without losing group boundaries. Missing labels never match; empty restricted models/isAnyOf reject. Reject unknown fields/operators/types rather than truncate. Bind page/search/user-filter fields in the signed body and reuse existing page validation/iteration. Apply authority before counts and heap, including metadata selection. Preserve unrestricted page behavior and native action overlays.

Withhold synthetic parents for any authority that is not effectively unrestricted; use actual producer/native parent markers, fail closed for incomplete evidence. Do not query History. Preserve unrestricted parents.

Pin normalization semantics and shared JSON parity fixtures for case, accents, Unicode expansion, trailing spaces, missing values, long values; document that Python/SQL consumes this contract in OSC-104. Follow established casefold matching where possible, never assume MySQL collation equals Go folding. Specify duplicate-label existence semantics for the future SQL consumer.

Update OpenAPI source and runtime capability evidence consistently. Follow repository generation rules; if regeneration requires prohibited Docker/build execution, do not hand-edit generated files: record exact pending generation steps and keep draft/activation blocked. Inspect existing handwritten routes/schema conventions before choosing registration.

Write focused tests first at api/v2 for AC-1 pre-limit/count/metadata, AC-2 role union + narrowing, AC-3 signature boundary negatives, AC-4 restricted parents, AC-5 strict validation/normalization fixtures, AC-6 route/capability/read-key behavior with actions disabled. Include actionView/ProviderSource regression. Tests remain unrun under execution limits.

Update native contract documentation and AC-to-test evidence. Self-review and commit with Corey identity, no AI attribution. No push or PR by implementer. Controller performs independent review and draft PR handoff.


## Generation status

The controller ran the repository's pinned native Swagger source generator. Go server, client, models and embedded Swagger now include the scoped operation. The handwritten generated-operation fallback returns 401 when the private read guard has not verified the original request. After execution was authorized, the pinned Elm generator and frontend assets completed, the generated scoped request compiled directly, and its three wire round-trip tests passed. The focused native API tests passed with race detection. Companion integration and repository-wide validation remain pending.
