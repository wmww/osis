# Single-use links: the link carries no single-use flag
> Summary: spec/permissions.md §9 makes single use a redeemer's act (the redemption removes L's own edge in the same commit), but the link format (spec/wire.md §10) has no field saying the link is single use, so a redeemer cannot know. The API ends single-use links from the sharer side, `FINALIZE_DELAY_MS` after it sees a joiner (a second redeemer within that window gets in). Owner call: add a flag to `Link` (format change) or keep the sharer-side reading.
> Tags: api, permissions, owner-call

- Today (crates/osis/src/share.rs `upkeep_links`): the sharer node remembers which links it made single use; on a roster change of K with a member other than L and the sharer's actor, it notes the time; `FINALIZE_DELAY_MS` (10 min) later it finalizes (removes L, K rotates). The delay exists because finalizing at once raced the joiner: K rotated before the joiner had reached the target's label and the joiner stayed out (node-sync: the hinted open of the target's label failed, issues/node-sync-gaps.md).
- Option A (spec as written): `Link := [1, seed, target, k, k_label, [address*], [peer*], single_use?]`; redeemers pass `single_use` to flows' `redeem`, which already removes L in the same commit. Needs a wire.md §10 edit and a vector update.
- Option B: keep the sharer-side reading and say so in spec/permissions.md §9.
