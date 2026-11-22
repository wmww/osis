# invalid-missing
> Summary: workflow notes from dropping missing parts judged invalid.

- `Meta::valid` is one bool for "judged invalid" and "unjudgeable"; every reader that needs the difference has to call `apply::unjudgeable` beside it. A re-judge that leaves a flag unchanged indexes nothing, so a judgeability change with no flip needed its own hook in `rejudge_once`.
- Evidence's property takes `OSIS_HELD_START`, not an `OSIS_EVIDENCE_*` name: easy to offset the wrong variable.
