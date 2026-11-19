# g-heldset
- `OSIS_ORDER_SHRINK=1` on a 60-step plain seed reruns the whole seed check (~15 s, all cores) per dropped step: 12 min for one seed (60 -> 8 steps), 23 min for another (60 -> 27). A shrink that replayed only the failing held set and order would be far cheaper.
- `pulled_anew` (the test peer's stand-in for a sync ID pulled anew) is never delivered by the order harness's `fetch_missing`; harmless here, but a node relying on a pull anew would fail the property with no hint.
