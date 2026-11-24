# OSC-117 independent code discovery, round 1

**NOT READY for code acceptance.** Three introduced defects remain open. The first exposes an excluded alert's identifier on an authorized record. Runtime, generated-interface and companion evidence also remain outstanding.

## Scope and identity

Fresh independent source review of the single implementation task and whole branch. The comparison uses explicit revisions b3cf31d9db656f34c442e321cd06f71a551d65c7 and d5631b4fbdd3096724e5230898c9f41dbce6f992 on cmetech/alertmanager. The nine paths and SHA-256 values in the adjacent manifest cover all product changes and the plan. The packaged diff matches the Git diff with ten context lines. The only untracked status entry is the excluded review directory. Origin, revisions, changed paths, file hashes and status were checked before and after, with no product drift.

## Spec

AC-1/2. ProviderSource authorization precedes actionView, user filtering, heap admission and total in api/v2/oscar_page.go:197. Both maps use the selected page. The groups retain independent AND/OR semantics. Nested record metadata still exposes an excluded source (F1).

AC-3/4. The HMAC binds method, path, audience, actor, timestamp and body digest. Read enrollment uses the operator key with the action owner disabled. Explicit unrestricted with no denials preserves current parent behavior. The restricted path checks the identity, event, role and aggregate markers used by the correlator's synthetic emitter. Ordinary child correlation references do not disqualify the child. Admission has an availability defect (F2).

AC-5. Typed validation rejects missing or empty groups, unsupported operators and invalid membership values. The same existing matcher handles folded label names, exact folded values and existential matches. The shared fixture covers seven cases. Malformed escaped Unicode can acquire a different meaning during decoding (F3).

AC-6. The OpenAPI source and handwritten handler agree on the POST operation, signing headers and success capability. Generated artifacts and actual caller execution remain pending.

## Standards

The change reuses the existing page pipeline, error responders, grid matcher and key enrollment. The changed-path list contains no hand-edited generated files or new dependencies. The repository API generation and verification requirements in AGENTS.md remain outstanding under the approved source-only plan. F2 concerns bounding work at the new trust boundary. No separate style finding.

## Findings

**F1 · High · High confidence. Restricted records reveal excluded inhibitor fingerprints.** The candidate's test already builds the case at api/v2/oscar_page_test.go:435 and :522. The persisted major alert inhibits the persisted minor alert through their effective projections. The restricted caller may see only minor. inhibit/inhibit.go:245 records the inhibitor fingerprint, api/v2/api.go:795 preserves it, and api/v2/compat.go:179 copies it into the authorized row returned at api/v2/oscar_page.go:269. The hidden alert is absent from the page and maps, but its canonical identifier appears in records[].status.inhibitedBy. The restricted assertion does not inspect status. The baseline GET intentionally exposed this relation to unrestricted readers. For restricted responses, retain the target's suppressed state and omit inhibitor references whose authority cannot be established. Extend this fixture to check the response contains no hidden inhibitor identifier and the unrestricted case retains the reference.

**F2 · Medium · High confidence. Incomplete request bodies can monopolize scoped-read capacity.** api/v2/oscar_scoped_page.go:177 acquires a slot before reading the body at :184 and releases it only when the handler returns. The byte limit bounds size, not duration. Even timestamp and HMAC validation happen afterward. The native server sets a header timeout at app/app.go:566, and the default web timeout is zero at cmd/alertmanager/main.go:81. Consequently stalled clients can exhaust scoped-read capacity and healthy signed reads receive 503. This semaphore and route are new. Bound body-read duration at this route with a deadline that actually interrupts the read and is cleared afterward. Check in an authorized runner that incomplete bodies expire and a normal read then succeeds without waiting for the stalled clients to close.

**F3 · Medium · High confidence. Unpaired UTF-16 escapes silently change authority literals.** api/v2/oscar_scoped_page.go:208 uses decodeAction (api/v2/oscar_actions.go:226). Raw UTF-8 validation accepts ASCII JSON escape syntax. Both JSON comparison passes use Go's encoding/json, which replaces an unpaired surrogate escape with U+FFFD. The equals decoder at api/v2/oscar_scoped_page.go:76 and the grid parser therefore treat a malformed escaped literal as the valid replacement character. A signed allow group with that malformed literal can match a persisted label containing actual U+FFFD, violating exact-value and invalid-policy semantics. This is new use of the baseline decoder for authorization policy. Reject unpaired surrogate escapes before lossy decoding, while retaining valid surrogate pairs and literal U+FFFD. Add boundary cases covering all three and check the malformed case returns 400.

## Evidence gaps and disposition

F1, F2 and F3 are accepted as supported by this reviewer at d5631b4f and open for author disposition and closure. None has been fixed or waived. All three conclusions are source-derived.

Required evidence remains pending for focused and repository Go tests, lint, generated server/client/models and embedded Swagger, Elm assets, and actual generated-client requests. Run the authorized generation workflow, inspect registration and verify fail-closed dispatch. OSC-104 must demonstrate trusted role resolution and signing, deployment key enrollment with mutations disabled, and Go/SQL parity against the shared fixture. OSC-105 must demonstrate browser gating of unrestricted REST and Connect routes. The branch alone cannot establish deployment readiness.

The next code action is to correct F1–F3, extend the focused coverage, and present the new revision for independent closure. Retain the draft and activation gates pending generated and cross-service evidence. No services, tests, builds, containers or live probes were run.
