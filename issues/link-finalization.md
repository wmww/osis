# A single-use link cannot be finalized by a plain removal
> Summary: spec/permissions.md §9 finalizes a used single-use link by a sharer device's plain removal of L, but L's redemption already removed L's `/members` entry, and a map remove of an absent key yields no delta, so there is no edge write to carry the frontier. Until decided, a single-use link stays honest-client-only after its use (the accepted residue). Owner to pick.
> Tags: owner-call, permissions, crdt

## Problem
The redemption's self-removal resets L's entry. The sharer's later `Op::Remove(L)` on `/members` finds no live entry, so `Engine::commit` writes nothing (checked in `crates/osis-node/tests/flows.rs::link_redeem_single_use_spec_perm_9`). perm needs an explicit edge write on (L, K) to audit forged earlier redemptions (§5.1, "as if the member still held the role"). `until` links are fine: the expired edge stays in `/members`, its removal carries a frontier (`Engine::finalize_link`).

## Options
1. A put of L's edge with `until` at or before the redemption: an explicit write by K's admin that leaves L with nothing; perm already treats a value expired when written as restoring nothing. No wire change; needs a spec sentence ("finalize by a plain removal, or after a self-removal by writing an expired edge") and a check that perm attributes it as an explicit demotion of L.
2. Let a remove of an absent key emit a reset of the key's dead entry dots (crdt change: removes become non-idempotent writes).
3. Accept: single-use finalization exists only for the `until` form; a forged earlier redemption stands until K is rotated and the forger removed by hand.

Recommended: 1 (no new mechanism, writer-side only).

## Meanwhile
`Engine::finalize_link` returns an error when L has no edge left; `revoke_joiner` skips L then.
