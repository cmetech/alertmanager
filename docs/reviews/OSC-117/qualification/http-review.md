# OSC-117 scoped HTTP review

Reviewed `504b43ed..0dfd107e70b416bbe17ce35fd35ab88bd879bcc4`. The diff gives the scoped route a transport read deadline before header validation, retains that deadline on incomplete requests, and checks the generated client against a real loopback server. I traced the registered route through the timeout wrapper and checked the Go 1.27.0 HTTP/1.x and HTTP/2 server behavior.

## Findings

1. **High — HTTP/2 rejection drains the shared connection.** `api/v2/oscar_scoped_page.go:226` sets `Connection: close` before validation for every protocol. Go 1.27.0 sends HTTP/2 GOAWAY when a handler sets that header (`src/net/http/internal/http2/server.go:2589`). One rejected scoped request can therefore make a multiplexed connection refuse new streams for its other API calls. The HTTP/2 implementation already applies `SetReadDeadline` to the individual stream. Set and clear the connection-close header only for HTTP/1.x. Exercise a rejected HTTP/2 scoped request followed by a new request on the same connection.
2. **Medium — Documented 408 and 503 distinction does not hold on HTTP/1.x.** `docs/alerts_api.md:135` promises a 408 when the body deadline expires before the web timeout. Go's HTTP/1.x connection reader cancels the parent request context on a read error (`src/net/http/server.go:809`), and `http.TimeoutHandler` can return 503 if it observes that cancellation before the scoped handler finishes. The real transport regression test explicitly accepts either response at `api/api_test.go:380` while using a one-minute web timeout and five-second read deadline. If either status is the supported contract, document the transport cancellation case in the API guide and OpenAPI 503 description. If callers require 408, preserve the distinction at the timeout-wrapper boundary.

The HTTP/1.x fix keeps the read deadline active while the server tears down incomplete requests and clears it only after the body has been read. The current real generated-client test proves typed scalar and list transport with connection reuse. The stalled-body test exercises the valid-header timeout and the prompt untrusted-sender rejection. These findings are independent of the existing full-suite fixture failures.

Reviewed source and platform behavior using the frozen diff. `git diff --check 504b43ed..0dfd107e` exited 0. The implementation author's scoped race result is recorded in `docs/reviews/OSC-117/validation.md`. I did not repeat those tests for this review.

## Follow-up on d947d1fb

Reviewed `0dfd107e..d947d1fb`. The HTTP/2 finding is closed. Only HTTP/1.x responses set or clear `Connection: close`. The new TLS regression checks the negotiated HTTP/2 protocol, a 401 on each stream, and reuse of the same connection on the second request. The captured red run fails the reuse assertion on the unguarded implementation. The implementation author's focused race run passed after restoring the guard.

The API guide now explicitly covers the HTTP/1.x 408 or 503 outcome when a body timeout cancels the request context. This closes the misleading client-facing guarantee. One low-severity documentation gap remains in `api/v2/openapi.yaml:285`. Its 503 description lists overall timeout, concurrency, and unsupported transport deadlines. It omits the documented transport cancellation case. Adding that case and regenerating the artifacts would align the descriptions. The schema already models the 503 response, so this does not affect the generated client's ability to receive it.

No new code findings in the correction. `git diff --check 0dfd107e..d947d1fb` passed. The red log and the recorded focused green result supplied the regression evidence for this review.
