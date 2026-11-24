# OSC-117 independent code closure, round 3

**INCOMPLETE for code acceptance.** F4 is addressed in source. The generated Go interface and its unauthorized fallback introduce zero supported findings. Execution, Elm assets and companion integration remain outstanding.

## Identity and scope

The independent discovery reviewer examined the 19 paths in the adjacent manifest between explicit revisions 89753bd8a084ceb68ac65208779956ce207e77a0 and 0be3dbd1ce37812a43cee8542a33dbe7d6596b6c. The original branch baseline is b3cf31d9db656f34c442e321cd06f71a551d65c7. The reviewed delta includes the timeout correction and the controller-generated Go interface. Origin, revisions, changed paths, file hashes, working-tree status and packaged diff matched the manifest before and after review. The review directory is excluded.

## Spec

**F4 — ADDRESSED at 937b460d, retained at 0be3dbd1.** The wrapper in api/v2/oscar_scoped_page.go:45 sets no-store on the transport writer before the configured web timeout starts. If the overall timeout wins, the inner capability header stays on the discarded timeout writer. The document and schema now describe 408 for the body timeout and 503 for the overall timeout. TestScopedPageOuterTimeoutHeaders exercises the registered prefixed route and checks committed headers. The separate direct 408 assertion remains. F1–F3 retain their round-two dispositions.

**AC-6 native Go source.** Both embedded specifications contain the scoped operation and the same response code set as the YAML. The generated client sends POST to the scoped path, writes the six assertion headers and typed body, and exposes the scoped version response header. The generated request can represent empty allow/deny arrays, explicit false, and either kind of rule value. The signed handler enforces the operator-specific value and policy constraints. A caller using the generated client must sign the exact bytes its producer transmits.

**Authentication boundary.** InstallActionOwner wraps the generated handler with the raw-byte verifier. In the generated operation, binder failure returns an error and successful binding dispatches only to the registered callback. NewAPI binds that callback to unconditional Unauthorized at api/v2/api.go:167. Neither path can invoke paging. TestScopedPageGeneratedRouteRequiresReadGuard intentionally uses NewAPI before middleware installation to cover a well-formed request with assertion headers.

## Standards

The implementation report records Go generation through scripts/swagger.sh. Generated client, server, models and embedded specifications accompany the YAML source. The explicit handwritten fallback follows the neighboring private-action pattern. The timeout check uses the existing standard-library virtual-time test infrastructure. No new standards findings.

## Dispositions and evidence gates

F1–F4 are addressed in source. No unresolved source finding remains in the reviewed rounds. Go generation is complete. No tests, builds, services, live probes or containers were run by this reviewer.

Next, obtain authorized evidence for the focused api and api/v2 cases, actual HTTP deadline and connection reuse behavior, generated-client signing through the registered server, and repository tests/lint. Complete the Elm asset workflow. Verify OSC-104 role resolution, key provisioning, signing and database parity, plus OSC-105 browser gating of remaining native routes. Keep the change draft and activation gated until the applicable evidence is available.
