# A redeemer offline across a rotation and the public's removal never hears it
> Summary: A node reading X by the public alone, offline while X's read keys rotate (the public boxed again) and then the public is removed, stays at the epoch it held, reading X's old value for good: its lapsed read secret opens, yet no entry past its own position reaches it.
> Priority: normal
> Tags: sync

Repro: osis-sync `differential::repro_a_redeemer_misses_a_rotation_and_the_public_removed` (ignored). Without the rotation the removal is heard (`a_redeemer_hears_the_public_removed_*`). The rule itself holds in held-model `closure::public_epochs` `Heard` (`a_reader_by_the_public_offline_at_its_removal_hears_it`, second history): the gap is in the build.

Seen while tracing (node 1 the redeemer): the lapsed Hit on its epoch is accepted and ended with an `until` past the removal, but node 1's reported position at that source is already past `until` (moved there by an earlier member opened by the public entry), so the member closes at once and nothing is served; node 1 has nothing pending. Likely cause: a reported position advanced past entries a member never served (an ended member's stream skipping what lies past `until`), then taken as where a later member of S starts. Look at spec/sync-opens.md §6 (Where it stopped, reported positions) against what an ended member's stream reports.
