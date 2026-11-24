# OSC-117 native qualification

Source `2a967d97f17ee0b2ae57a42ed08f529a303e59c9`. Comparison base `b3cf31d9db656f34c442e321cd06f71a551d65c7`. Commands and exit statuses are in the sibling logs. All tests run locally in the native worktree using ephemeral test fixtures. Existing live services were untouched.

| Gate | Result | Evidence |
| --- | --- | --- |
| Full Go race suite | Exit 1. Go 1.27.0 recorded 54 passing packages, 30 with no tests and five failing packages. All five have matching base reproductions. The frozen source archive uses the repository release version in the local amtool fixture and the standard 10-minute per-package timeout. Two superseded runs were stopped after the replacement launched. | `go-ci-standard-timeout.log`, `superseded-go-attempts.log` |
| Go lint | Exit 1 on both revisions with golangci-lint 2.14.0. Head adds two gofumpt findings to 98 reproduced on the base. | `lint-unlimited-retry.log`, `baseline-lint-unlimited.log`, `lint-diff.txt` |
| Mantine check, tests, TypeScript and production build | Exit 0 under Node 24.19.0. Biome reported six warnings and two infos in unchanged Mantine files. All 61 tests passed. | `mantine.log` |
| Elm source formatting, lint, tests and production build | Exit 0 under Node 24.19.0 using the lockfile-installed binaries directly. All 70 tests passed. The default Make invocation segfaulted after starting its npx-driven recipe. The same Make test target passed with `NPX=` and the installed binaries on PATH. | `elm-make-local.log`, `elm-build.log`, `elm-format.log`, `elm-review.log`, `elm.log` |
| Branch whitespace | Exit 2. Two formatting findings in captured validation output at lines 3 and 28. | `whitespace.log` |

Apply the repository gofumpt rules to `api/api_test.go:259` and `api/v2/oscar_scoped_page_test.go:34`. Trim the trailing whitespace and final blank line in `docs/reviews/OSC-117/round-4/validation-output.txt`. The baseline lint comparison used a temporary git archive and copied compatible embed assets into it.

## Existing Go test failures

- `./cli`: `TestDefaultConfigFilesOthersWithXDGConfigHome` expects a path under `XDG_CONFIG_HOME`. On macOS, `os.UserConfigDir` returns `$HOME/Library/Application Support`. The same assertion failed on the base. Align the test with the platform-specific path if it is intended to cover macOS.
- `./ui`: The two `TestMantineIndexAssetsAreServed` variants treat the OSCAR AdminUI favicon endpoint as a bundled static asset. HTTP 404 reproduces with the base source and the same unchanged Mantine bundle. Qualify bundled files separately from the OSCAR-origin branding URL in those tests.
- `./test/cli/acceptance` and `./test/with_api_v2/acceptance`: The same 10 tests failed on both revisions because silence writes returned 403 or downstream assertions depended on a silence write. The existing native silence-mutation guard requires a test credential; the acceptance fixture cannot currently authenticate its writes. Provision a fixture-only key and include its authentication header on test writes. See `baseline-go-acceptance.log`.
- `./app`: The same two race detector stacks reproduce on both revisions when running the app package with only its four minute-scale commissioning tests excluded. The ordinary notifier calls `terminalFixtureJournal.reservation` while direct invocation calls `terminalFixtureJournal.Claim`. Both append to the same fixture events slice at lines 387 and 416 of `app/oscar_timing_reloader_test.go`. Go attributes the race to multiple overlapping tests. Protect shared fixture state and its observations or stop the asynchronous notifier before making fixture assertions. See `head-app-without-long-fixtures.log` and `baseline-app-without-long-fixtures.log`.
- `./app`, full suite: On both revisions the standard 10-minute limit expired in `TestOscarActionCommissioningThroughAppAndProvider`, blocked in the same `next("direct-only", false)` call at `app/oscar_action_publication_test.go:1122`. The candidate was 9m52s into that scenario after the other app tests ran. The base had the full 10 minutes in the single-scenario control. The remaining three minute-scale scenarios did not run in the candidate suite. To qualify them separately, give the commissioning tests their own job budget covering group intervals and the terminal test's configured 10-minute expiry. See `go-ci-standard-timeout.log` and `baseline-app-first-long-fixture.log`.
- Five MailDev integration cases were skipped without the CI mail fixture. The STARTTLS case has an explicit skip for the local MailDev behavior.

See `baseline-go-failures.log` for the base reproductions.

## Transport coverage on the frozen qualification SHA

`TestScopedPageRegisteredWithWebTimeout` in `api/api_test.go` exercises the registered `/am` route with a response recorder whose deadline setter appends timestamps. The adjacent outer-timeout test exercises header behavior with a blocking stand-in handler. The v2 tests cover signed raw bodies and the unsigned generated server guard. No existing test calls the generated `GetOscarScopedAlertsPage` client or verifies an actual connection's deadline behavior.

Extend the existing API-level fixture with `httptest.NewServer(api.Register(route.New(), "/am"))`. Configure the generated client base path as `/am/api/v2` and use `NewGetOscarScopedAlertsPageParamsWithHTTPClient(server.Client())`. Serialize typed request params with the same go-openapi JSON producer used by the client, including its terminal newline. Compute the read signature over those exact bytes and canonical `/api/v2/oscar/alerts/scoped-page`. Check typed response and scope result, `Cache-Control: no-store` and the scoped-version header. Repeat using a single HTTP/1.1 transport, collecting `httptrace.GotConn`, and delay the repeat beyond the first request's read deadline to detect stale deadlines. Exercise a separate raw localhost request that sends valid read headers and stalls within its declared content length. Bound the test client read deadline, verify the appropriate 408 or outer 503 and required headers for the configured timeout, and show a subsequent fully signed request succeeds.

The later HTTP candidate `0dfd107e` adds real generated-client and stalled-body coverage and fixes an HTTP/1.x body drain that the recorder did not expose. The independent review of that narrower candidate is in `http-review.md`. The full-suite results above apply to the older, frozen `2a967d97` source.

## Subsequent closure

Formatter commit `504b43ed` corrected both introduced gofumpt findings and captured-output whitespace. Product commits `0dfd107e` and `d947d1fb` add real generated-client HTTP/1.1 and TLS HTTP/2 coverage, bound incomplete bodies through teardown, and preserve healthy connections. Independent narrow review closed both HTTP findings. A low OpenAPI-description omission (503 may also result from HTTP/1.x context cancellation) remains; the API guide documents the behavior and generated clients already accept 503. The test-only pointer helpers use native new expressions required by the pinned linter. Focused client/HTTP2 race tests passed (1.652s). Final golangci-lint 2.14.0 comparison reports exactly the same 98 baseline findings, with zero added or removed findings.

Full-suite results remain an explicit failure, with base reproductions rather than a clean CI claim. Three long app scenarios and MailDev cases remain unexecuted. No merge/deployment/production service restart.
