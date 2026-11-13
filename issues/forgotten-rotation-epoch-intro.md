# A forgotten actor's rotation stays in epoch_intro
> Summary: When a released actor with secrets of its own is forgotten whole and a commit acting for it is held, its rotation commit goes (`forget_released`, `unindex_commit`) but its `epoch_intro` rows stay, naming a commit no longer held: the persisted index then differs from one rebuilt from the commit records, and a debug build panics in `Engine::check_index` at the next open.
> Priority: normal
> Tags: engine, tests

- Reproducer: `destruction::a_destroyed_actors_secrets_go_with_the_last_entry_of_its_commits_*` with, after `net.grant(a, t, tb, Role::Admin)`, b committing `m.set(g, &REG, ..)` with `m.act_as(t)`: `net.restart(b, 50)` panics (`Table("epoch_intro")`, t's epoch 2 by the grant's rotation commit). Without the acting commit the same test opens clean.
- `unindex_commit` does not re-derive the keysets of an actor whose `keys.0` part it unindexes (`apply::keys::rebuild_keysets`); something else clears them in the plain case. Find what, and make unindexing do it.
