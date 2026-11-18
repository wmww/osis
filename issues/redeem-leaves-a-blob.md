# A redeemed and ended link leaves storage behind
> Summary: After a link is redeemed, ended and everything let go, the grantee keeps one blob of the sharer's account creation commit more than a fresh world, and the sharer's seed thing has no way to be let go (no API releases it). Repro: osis-sync `growth::repro_a_redeemed_and_ended_link_returns_storage_to_a_fresh_worlds_spec_sync_set_3`.
> Priority: normal
> Tags: sync, engine, retention

Releasing everything returns storage to a fresh world's (issues/storage-owners.md). The repro's first round grants by a link (`growth::redeem_round`): node 0 makes the thing and a read link, node 1 redeems it, node 0 ends the link (`finalize_link`) and takes K off the thing, node 1's account leaves K, and both drop every strong the round wrote.

- **Grantee**: one more `bp/` row (blob parts) than a fresh world, of the sharer's account creation commit (6 blobs held of it against 5), at 2 and at 20 rounds: one round redeems in each, so whether it grows per redeem is not yet known. Likely a copy taken under K's sync ID (the sharer's chain K carries) that stays once K's sync ID leaves. Find under which sync ID it is held and why it stays.
- **Sharer**: the link's seed thing (`create_link`'s keep thing, minted with admin D, held from D) stays after `revoke_link`; nothing in the API lets it go, so each link made holds a thing forever. The repro drops its strong by hand. Decide: the seed thing goes with the link's end (it serves only a live link), or `revoke_link` releases it.

Once both are fixed, fold the redeem round into the grant arm (`grants_as_fresh(true, true, 4)` in `a_granted_and_revoked_thing_returns_storage_to_a_fresh_worlds_spec_sync_set_3`; the separate arm costs about 50 G instructions, the fold one round's worth).
