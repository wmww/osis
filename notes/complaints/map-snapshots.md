# map-snapshots
> Summary: mishaps met fixing the map/expiry/snapshot arrival-order family.

- `repro_expired_residue_order_spec_crdt_4_7` indexed a generated history (`history(seed, 60)`); `random_step` had moved on and it passed on main before any fix, so it tested nothing. Deleted; a repro should pin its shrunk `h = vec![..]`.
- The `Nested` step's inner write and snapshot run without `tick`, so a peer's expiry timer never fires inside `play`: an author's state past T still holds its values until the snapshot writer strips them. Fine for the harness, but it hid where 4136's snapshot lost the write (un-merge at the writer, not expiry).
- Diagnosing needed a body dump per commit (`Engine::body_fragment`, test-only): `aspect_dump` shows the state and statuses only. Added, then removed with the diagnostics; worth keeping next time it is needed.
- A seed that fails as made with the whole set held shrinks for 90-100 s before printing: run the diagnosis on the full `history(seed, 60)` first.
- Review: a failing alike seed shrinks for up to 9 min under load (98057, 40046) before printing; several in parallel to get their messages took longer than the oracles themselves.
- Review: the per-branch oracles never reached the expiry-recompute cost (their maps are tiny); an ad-hoc scale probe under `tools/icount` found an 8x regression. A branch that adds a recompute trigger needs a cost check by hand.
