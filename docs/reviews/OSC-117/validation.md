# OSC-117 validation and handoff

Latest product candidate: HTTP deadline correction following `504b43ed` (commit linked by subsequent review).
Base: `b3cf31d9db656f34c442e321cd06f71a551d65c7`.
Corey explicitly authorized Elm/asset generation and focused Go tests on 2026-11-24.

## Completed checks

| Check | Result |
| --- | --- |
| Pinned Go OpenAPI generation, `bash scripts/swagger.sh` | Passed; generated client/server/models and embedded specs included |
| `fnm exec --using=24.19.0 make assets` | Passed; local container-based Elm generation, formatting, Elm and Mantine builds |
| Explicit `elm make src/Data/OscarScopedPageRequest.elm --output=/dev/null` from ui/app | Passed; new generated types compile even though the current UI does not import them |
| `elm-test tests/OscarScopedPageWire.elm` under pinned Node | Passed: 3 tests, 0 failures |
| `go test -race ./api ./api/v2 -run 'TestScopedPage\|TestScopeParityFixture\|TestEffectiveFingerprintCollisionThroughReadHandlersAndTiming' -count=1` | Passed both packages; shell alternation uses plain pipes |
| Formatting, whitespace, OpenAPI structure and embedded-source checks | Passed |

Captured final focused output is in round-4/validation-output.txt. Independent source discovery/closure evidence remains in rounds 1–3; the generated Elm correction is reviewed in round 4. Later evidence-only commits do not change product behavior. Generated files were not hand-edited.

## Failures reproduced and corrected

The first v2 test invocation could not compile because the fresh worktree lacked embedded ui/app/dist assets. Asset generation supplied the prerequisite; subsequent focused runs passed.

The ordinary UI build passed while the new unused request type contained an undefined Object reference. Compiling that module explicitly reproduced the failure. The source schema now opts its polymorphic filter value into Elm's native JSON value type, preserving strings and arrays. A second focused regression exposed absent logicOperator being encoded as null; a property-specific generation annotation now omits it. Both fixes are in source templates/schema, with regenerated output. Scalar/list values and omitted/explicit AND/OR logic all pass round-trip checks. Existing generated Elm models had no changes.

The scoped Go tests exercise signed boundaries, role groups, parent/child visibility, inhibitor references, read-only key enrollment, malformed Unicode and timeout behavior, including race checking. This is focused evidence, not a claim that the entire repository or deployment has passed.

## Remaining gates

- Repository-wide tests/lint qualification is in progress; baseline failures are recorded separately.
- OSC-104: fresh grouped authority, trusted signing, read-key provisioning with mutations disabled, SQL normalization parity and full read/action/report enforcement.
- OSC-105: native-console/alternate route gates and scoped UI behavior.
- Complete activation coverage and rollout checks, including artifact downloads and Grafana separation. This native PR does not activate restrictions.
- GitHub Actions remain disabled. This checkout has no GitLab remote or pipeline file; no hosted CI ran. A GitHub push is not CI evidence.

The isolated worktree/branch remain for draft PR review. No live OSCAR service restart, deployment or merge was performed or authorized by this validation work.

## Real HTTP qualification — 2026-11-24

The generated Go client now runs against the registered `/am` server over TCP. Signing uses the actual JSON producer (including its trailing newline), scalar/list Unicode rules, both response contract versions, and a reused connection. An incomplete authenticated TCP upload reproduced a ten-second response stall; a seven-second goroutine capture showed net/http draining the body in chunkWriter.writeHeader after the scoped handler had cleared its deadline. The handler now preserves the deadline for incomplete bodies and closes rejected unread requests. Complete bodies clear the deadline and retain keep-alive. Early unauthenticated incomplete requests return 401 within the two-second test bound; authenticated stalled requests return 408 or the surrounding TimeoutHandler's 503 at the five-second body deadline, without a success-version header and with no-store.

`go test -race ./api ./api/v2 -run 'TestScopedPage|TestScopeParityFixture' -count=1` passed after the correction (api 6.880s, api/v2 1.940s). The net.Pipe regression asserts that failed reads retain the bounded deadline; it still exercises nine sequential expirations against the eight-slot budget and a subsequent successful request. Independent review follows this frozen change.
