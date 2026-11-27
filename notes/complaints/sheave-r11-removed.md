# sheave-r11-removed
> Summary: workflow snags from the removed-node differential classes.

- The trace filter `t<k>` hides every line without that thing's tokens, so `Shared`, `Lost` and `Notice` answers on a sync ID went unseen and I misread which side opened what; adding `Shared,Notice,Lost` to `<only>` showed it. A trace option printing a delivery's whole Offer/Shared pairing would have saved a round.
- `why_role` prints no holding or member state at the serving reader; finding that a departed peer's S stood open by the public entry (so nothing told it) took debug prints in `opens::judge` and `accept_by_role`. A probe line per member (class, by, departed, until) at each reader would show it.
- Deciding which of several fixes a hand test needs: `tools/mutate.py` with a revert-to-old expression per fix answered it in one build and found two of four fixes unneeded. Worth naming in briefs as the way to check "a test that fails without each fix".
