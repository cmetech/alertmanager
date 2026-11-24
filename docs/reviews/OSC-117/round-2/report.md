# OSC-117 independent code closure, round 2

**NOT READY for code acceptance.** F1–F3 are addressed in source. One adjacent response-contract defect remains at the configured web timeout. Generation, execution and companion rollout remain separate gates.

## Identity and scope

The independent discovery reviewer re-read all eight fix paths between d5631b4fbdd3096724e5230898c9f41dbce6f992 and 89753bd8a084ceb68ac65208779956ce207e77a0. The original baseline is b3cf31d9db656f34c442e321cd06f71a551d65c7. Origin, revisions, paths, byte hashes, working-tree status and the packaged ten-line-context diff matched the adjacent manifest before and after review. Only the excluded review directory appeared in status. The original report remains intact.

## Spec and dispositions

- **F1 — ADDRESSED in source.** At api/v2/oscar_page.go:268, restricted projection builds the visibility set from selected ProviderSource fingerprints and filters the independently computed inhibitor list. It preserves suppression state and leaves unrestricted references intact. The revised collision fixture covers excluded and co-selected inhibitors. The child fixture explicitly preserves its own parent label.
- **F2 — ADDRESSED in source.** At api/v2/oscar_scoped_page.go:251 and :268, admission checks freshness first and bounds body reading using the transport's deadline. Failure to install a deadline returns immediately. Deferred release covers error exits. The outer controller and its lock handle the configured timeout writer and termination of an outstanding read. The pipe tests exercise deadline and subsequent capacity reuse. F4 below concerns the response emitted by the outer wrapper, independent of admission recovery.
- **F3 — ADDRESSED in source.** At api/v2/oscar_scoped_page.go:74 and :308 the scan checks escaped surrogate pairing before lossy JSON decoding. An escaped backslash consumes its partner, valid surrogate pairs survive, and literal U+FFFD remains valid. The signed-route assertions cover all three cases as well as isolated low and high surrogates.

AC-6 still has a source contract mismatch and outstanding generated and caller evidence.

## Standards

The change retains shared paging and ordinary GET behavior. Deadline plumbing uses standard-library transport control, applies to the scoped path, and handles a mount prefix. The scoped middleware tests cover the direct handler, while the registered-router test covers only a successful body with a long configured timeout. The OpenAPI source was edited without hand-edited generated outputs, consistent with the source-only plan. No separate standards finding.

## Adjacent finding

**F4 · Low severity · High confidence · Open, accepted by reviewer at 89753bd8.** The outer request deadline can produce an undocumented 503 without the promised cache directive. api/api.go:312 wraps the native v2 handler with api.limitHandler, which uses http.TimeoutHandler at api/api.go:406. With a positive web timeout shorter than five seconds, the body-read deadline and the outer request deadline can coincide (api/v2/oscar_scoped_page.go:268). If the outer timer wins, Go's net/http timeoutHandler.ServeHTTP writes 503 directly and discards the inner response headers. The outer scoped wrapper at api/v2/oscar_scoped_page.go:39 never sets Cache-Control. Thus callers can see 503 with no no-store header even though docs/alerts_api.md:136 promises 408 and :160 promises no-store on all scoped responses. This does not return alert data. The generic web-timeout behavior predates the fix, while the unconditional body-timeout guarantee is introduced in this revision.

Smallest correction: set no-store on the real response before entering the timeout writer on this path, document 408 for the body deadline and 503 when the overall request timeout wins, and include the overall timeout case in the OpenAPI 503 description. Verify the registered route's outer timeout response with a controlled inner handler or body, including no-store and absence of the success capability. Preserve the direct 408 test.

## Outstanding evidence

The checks above were source-only. Pending evidence includes focused v2 and api tests, an actual HTTP timeout/connection reuse check, repository tests and lint, generated server/client/models, embedded Swagger and Elm assets. OSC-104 must verify trusted signing, key enrollment with mutations off and SQL parity. OSC-105 must verify browser route gating. Correct F4 and review its narrow delta before code acceptance. Keep the draft and activation gates in place pending the outstanding evidence.
