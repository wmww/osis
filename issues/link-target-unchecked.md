# Redeem returns the link's target unchecked
> Summary: `Osis::redeem` returns the link text's target without checking that K holds an edge on it: a link with one chat's target and another's key joins the other silently and reports the named one.
> Tags: security, osis

A link's target is not bound to its key (spec/wire.md §10 carries it beside the seed; nothing signs the pair). `redeem` grants onto K, then waits only for `knows(target)` and the grant on K, and returns `target`. A link made by C2's admin with `target` set to a chat T the redeemer already knows joins C2 and reports T: the app opens T, and the redeemer holds C2 without seeing it. Found in review of app-rejoin: with the old `osis_chat::join` (plain `redeem`), `flows::join_held_target_redeems_nothing_kicked_rejoins` showed `chats` gaining C2. `osis_chat::join` now returns a held target without redeeming, so this needs a target the redeemer knows but does not hold as a chat.

Fix: after the grant, wait until K is on the target's roster (the edge the link is meant to give), else fail with the link named invalid; or check it before redeeming where K's edges are readable. The joiner still holds C2 on failure unless the check comes before the grant.
