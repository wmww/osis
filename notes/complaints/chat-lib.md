# chat-lib
- `required^.0` refuses `edit` ("written whole") at commit only; the typed key offers `edit` and path ops all the same. A compile-time or doc hint would have saved a test round.
- Existing osis sharing tests built "two ways in" by having a holder redeem a link to what it already held; changing `redeem` broke three tests whose setup leaned on that side effect.
