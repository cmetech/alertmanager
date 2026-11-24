# OSC-117 generated Elm correction, round 4

**READY for the Elm correction. Zero supported findings.** The generated request compiles and preserves the three valid group-logic forms and both supported rule-value shapes. Full-feature CI and deployment acceptance remain pending.

## Scope and identity

Independent review of 78042598be4ab589672d3a5051edcd339ccb65f7 to 98a0bfcfc4ae5162507ff72c22dae0b44857fd37. All 13 changed paths, SHA-256 values and the packaged ten-line-context diff matched the manifest. Before and after review, only the excluded round-four review directory appeared in Git status.

## Spec

The generated item decoder uses Decode.value and its encoder passes that value through. Equality retains its string, including accents and trailing whitespace, and isAnyOf retains the array and order of its strings. The generated group encoder drops only the logicOperator pair for Nothing and writes the corresponding lowercase enum for Just And and Just Or. Native verification and policy validation still apply to the actual signed bytes.

The regression decodes an entire request and encodes it through the generated modules, then inspects the result with independent, shape-specific JSON decoders. It checks key presence explicitly, so substituting null for absence fails. It also checks both rule operators, field names and literal values. These tests verify valid wire representations; they do not exercise a deployed caller signing them.

## Standards and evidence

The OpenAPI source opts only the scoped group and its polymorphic item value into the template changes. The generated diff adds four scoped Elm modules and leaves every pre-existing generated Elm model unchanged. Both embedded Swagger documents carry the matching annotations. The implementation record attributes the generated outputs to scripts/swagger.sh and the pinned make assets workflow.

The controller's final logs record a successful direct Elm module compile, all three wire tests passing, and passing focused race-enabled Go tests in api and api/v2. Earlier logs and the implementation record distinguish the initial compile failure and omitted-logic failure from the corrected results. This reviewer inspected source and recorded evidence without rerunning generation or tests.

The compile and wire defects are addressed at 98a0bfcf. F1–F4 retain their previous dispositions. Repository-wide tests/lint and CI, generated-client HTTP interoperability, trusted OSC-104 signing/key and SQL parity, and OSC-105 browser route gating remain separate whole-feature checks.
