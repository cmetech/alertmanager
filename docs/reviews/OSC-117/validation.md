# OSC-117 validation and handoff

Product source candidate: `0be3dbd1ce37812a43cee8542a33dbe7d6596b6c`.
Base: `b3cf31d9db656f34c442e321cd06f71a551d65c7`.

## Completed source checks

- Pinned Go OpenAPI generator: `bash scripts/swagger.sh`, exit 0. Generated Go server/client/models and both embedded specifications are included. Generated files were not hand-edited. The parsed-operation fallback denies requests independently of the authenticated outer route.
- `gofmt` on changed handwritten Go files; formatting check emitted no paths.
- `git diff b3cf31d9db656f34c442e321cd06f71a551d65c7 HEAD --check`, exit 0.
- Parsed source OpenAPI YAML; compared the generated embedded operation, response codes and parameters with source.
- Parsed shared JSON fixtures and checked Python casefold expectations as an offline fixture sanity check. This is not SQL/Go implementation parity evidence.
- Conventional commit/issue-reference checks passed for all four product commits. Git author/committer is Corey Ellis.

Independent discovery and closure evidence is preserved in round-1, round-2 and round-3. The reviewed revisions are explicit; later evidence-only commits do not change the product source.

## Authored runtime coverage — not executed

`TestScopedPage`, `TestScopeParityFixture`, `TestEffectiveFingerprintCollisionThroughReadHandlersAndTiming`, generated-operation fallback coverage, `TestScopedPageRegisteredWithWebTimeout`, and `TestScopedPageOuterTimeoutHeaders` cover the signed boundary, role groups, metadata, parent/child visibility, read-only key enrollment, malformed Unicode and timeout behavior. These tests have no recorded runtime pass or failure.

After execution authorization, run focused suites including:

```sh
go test ./api/v2 -run 'TestScopedPage|TestScopeParityFixture|TestEffectiveFingerprintCollisionThroughReadHandlersAndTiming'
go test ./api -run 'TestScopedPage'
```

Then complete applicable repository lint/tests, Elm generated types and asset checks. The Elm generator invokes a container and `make assets` builds the frontend. No service build, runtime test, service/container start, live probe or CI was performed during this work.

## Release gates

- OSC-104: fresh grouped authority, trusted signing, read-key provisioning with mutations disabled, History/SQL normalization parity and full read/action/report enforcement.
- OSC-105: native-console/alternate route gates and the complete scoped UI contract.
- Complete the original activation coverage and rollout checks, including artifact downloads and Grafana separation. This native PR does not activate restrictions.
- GitHub Actions are disabled. This checkout has no GitLab remote or pipeline file; a GitHub push/PR is not CI proof. Do not claim hosted checks without a deliberate configured run and matching SHA.

Retain the isolated worktree and feature branch for review. No merge or deployment is authorized by this handoff.
