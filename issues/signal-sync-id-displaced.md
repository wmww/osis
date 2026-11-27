# A grant signal's sync ID displaces another's
> Summary: A node follows a signalled thing under the sync ID of the newest held grant signal naming it, so a forged signal (anyone holding the holder's card) strands the honest one, and which one wins depends on arrival and, after a restart, commit ID order.
> Priority: normal
> Tags: security, engine

`FollowedLinks::follow_signal` (core/engine/src/sync_ids/actors.rs) keeps one sync ID per signalled thing X, overwritten by each signal followed; `drop_signals` reloads rows in commit ID order. A `grant@~0` fire on an inbox whose setting enables it may be fired by anyone holding the holder's card (spec/sync-inbox.md §2), so a forger naming X with a sync ID of its own makes the holder follow that one alone: it never enters X by its real grant while the forged signal is held. spec/sync-hostile.md says a forged signal "names a sync ID that gives nothing"; it also takes away the honest one's.

Test: `sync_ids::actors::tests::a_signals_sync_id_is_never_displaced_by_another_*` (ignored, fails).

Fix: follow X under every sync ID a held signal names (as a node keeping a thing unread syncs every sync ID it keeps for it, spec/sync-ids.md §2), each let go with the last signal naming it; the owner rule (spec/sync-ids.md §4 Owner) already judges which is X's. `by_k` then maps a thing to a set of sync IDs.

Related: a signal's peers are dial hints (`Engine::signal_hints`), so the same forger makes the holder's node dial addresses it chose, learning that it is online and where; spec/sync-hostile.md states neither.
