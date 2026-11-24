# Native human action scope qualification

The paired action implementation is reviewed at native `6d13359b01f3f486baee78e8d4b9ddc00d649deb` and OSCAR backend `8ca4b2cc11af038eb0bc75986865a1df7f066fd1`. This supplements the earlier scoped-read evidence. It does not enable restrictions or qualify the unfinished backend and UI consumers.

## Behavior and release pairing

Human operator requests carry separately compiled read and action policies bound to the signed method, path, actor and immutable command body. Native checks the actual current provider source before reservation and inside the existing provider-locked callback immediately before submitting one immutable command. A change after that decision can precede the original durable write, subject to existing transactional guards. Later mutations, renewals, recovery attempts and provider contacts require fresh authority. This is request-snapshot authorization, not a distributed commit-time lock on roles or source labels.

Recovery derives the actor and command from the persisted operation. The paired Python owner and middleware exchange a short-lived, nonce-bound authenticated decision; neither a queued policy nor a caller-supplied actor grants access. The native `contact-check` endpoint uses a purpose-separated signed response with a fresh nonce and exact request echo. Worker-to-owner and owner-to-middleware authority paths require verified TLS. Execute, lookup and eligibility retain request authentication; their responses do not carry the contact-check response MAC.

The leased claim-target request carries the transient human decision into the Python transaction that locks and verifies the original operation and complete History contributor set. A new out-of-scope contributor prevents provider entry. Worker notification sends and external receipt queries also require fresh exact-attempt authority. Already retained receipt settlement can complete without making another provider contact. Service and policy lanes retain their existing contracts.

Release together with OSC-104 and OSC-105. An older Python owner does not implement the new decision and recovery contract. Provision the existing operator and worker credentials and verified internal TLS before use. Restricted activation must remain disabled until all consuming paths and deployment exclusions are qualified; rolling back to software that ignores stored restrictions is unsafe after activation.

## Independent review

Specification and code quality passed at the frozen pair above. The initial review found three defects, all corrected and independently closed:

1. Direct native provider entry omitted the current History contributor check. The decision now reaches the locked claim transaction.
2. Reconciliation could make an external receipt query after revocation. Both external queries and sends now require fresh attempt authority.
3. An authority outage before first contact could record false uncertainty and strand an unsent notification. Proof is now acquired before entry and verified by the winning transition, leaving unattempted work recoverable.

Joined tests on MySQL 5.7 and 8.4 exercise actual Go Claim, the Python ASGI/SQL owner and a counted test provider. Contributor drift returns 403 with no token and zero sends; restoration returns 200, exactly one send and confirmed SQL state. Roles/current-source evidence and the provider transport are fixtures. This is not a full deployed TLS environment or a real external provider qualification.

## Current native qualification

Go 1.27.0, darwin/arm64; generated Elm compilation uses Node 24.19.0. The source freeze above passed both binary builds and compilation of the generated `OscarContactCheck.elm`. Pinned asset generation also rebuilt both interfaces.

The broad race run used `go test -p=2 -race -count=1 -timeout=10m -json ./...`, with the following four long scenarios excluded and executed separately with bounded timeouts. The broad partition passed 55 packages; 30 had no tests, and four failed for documented baseline causes. It recorded 2,433 passing test/subtest events, 27 skips and 15 failing events. Counts include subtests and are not unique test-function counts.

| Separate race scenario | Result |
| --- | --- |
| `TestOscarActionCommissioningThroughAppAndProvider` | Passed, 784.53 seconds; 4,109 firing members |
| `TestOscarActionLargeTerminalGroupThroughAppAndProvider` | Passed, 1,084.76 seconds; 4,109 terminal members |
| `TestOscarTerminalGroupShortIndividualPermitThroughAppAndProvider` | Passed, 162.52 seconds |
| `TestOscarDirectCohortExcludedSettlementPreservesProviderOutcome` | Passed, 4.42 seconds, accepted and rejected cases |

The first broad attempt exhausted local disk while linking. The reduced-concurrency run above completed; the earlier infrastructure failure is not a product result. The historical app timing-fixture race did not recur in the completed partition. A same-command baseline control also passed the firing commissioning case.

The four failing packages are `cli` (macOS/XDG path expectation), `ui` (external OSCAR favicon returns 404), `test/cli/acceptance` and `test/with_api_v2/acceptance` (silence writes rejected by fixture authentication, with resulting missing-silence assertions). These match the documented baseline causes. Isolated MailDev 2.2.1 runs on both the candidate and baseline each passed 54 events and reproduced four failing error-handling subtests plus their parent failure. STARTTLS remains explicitly skipped.

Other broad skips are 19 explicit matcher compliance exclusions, the opt-in joined-owner and TL1 lifecycle harnesses, and six email tests subsequently exercised by the isolated MailDev run except its explicit STARTTLS skip. The joined Go/Python claim qualification is recorded separately above. Skips are not passing proof.

Pinned golangci-lint 2.14.0 initially reported 99 findings versus 98 on baseline `2a2de20a`; the sole new finding was a redundant test-context assignment in `api/v2/oscar_action_owner_test.go`. Test-only correction `c67d2cea906eafc67a09357c93d5f74ea5526fc7` preserves construction of the authenticated context after projecting the episode reference. `go test -race -count=1 -run '^TestOscarActionPersistenceLossAndInvalidation$' ./api/v2` passed in 1.666 seconds. Pinned lint then matched all 98 baseline diagnostics with zero additions or removals after normalizing line and column positions. Lint still exits 1 for the baseline findings; this is not a globally clean lint claim.

Unchanged frontend test suites retain their earlier evidence and were not rerun for these backend action changes. No hosted pipeline is configured for this repository; no hosted CI pass is claimed. Full deployment TLS, remaining OSC-104/105 enforcement, and site isolation/activation checks remain pending. No merge, deployment or live OSCAR restart was performed.
