# Author dispositions

At d5631b4fbdd3096724e5230898c9f41dbce6f992, accept F1, F2 and F3 for correction before handoff.

- F1: preserve suppressed status but exclude inhibitor references whose alert access has not been established; keep unrestricted behavior. This is confined relation metadata handling, not parent field redaction.
- F2: interrupt stalled body reads and clear deadline afterward. The frozen candidate checks the timestamp after reading; check before admission and after reading as well. An earlier controller note referred to a prior working copy and was incorrect.
- F3: reject malformed surrogate escapes before the JSON decoder can replace them, preserving valid surrogate pairs and literal replacement characters.

Fixes require independent closure. Runtime proof and generated-interface validation remain pending; no finding is marked fixed yet.

F1 clarification: dynamically enriched inhibitor references require access checks; the permitted child’s own producer-supplied parent-fingerprint label remains visible. No arbitrary label redaction is introduced. Closure must assert the status relation, not a response-wide string prohibition.
