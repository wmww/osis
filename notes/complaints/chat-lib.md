# chat-lib
- `required^.0` refuses `edit` ("written whole") at commit only; the typed key offers `edit` and path ops all the same. A compile-time or doc hint would have saved a test round.
- Existing osis sharing tests built "two ways in" by having a holder redeem a link to what it already held; changing `redeem` broke three tests whose setup leaned on that side effect.
- Review: stopping a gate mid-build (to rerun after an edit) left `undefined hidden symbol` link errors; `cargo clean -p osis-engine -p osis-node -p osis` fixed it but cost a 6 GB rebuild. Edit first, then start the gate.
