# A holder's readers download every box of it and of everything it holds
> Summary: Two costs in the roster and in the things below a holder that no reader needs (measured, notes/holder-access-study.md Baseline): every reader of a thing fetches every box of each of its rotations (4.9 KB per remaining writer, 4.9 MB at 1,000), and a holder's sync ID carries the whole `secrets.0` part of every rotation of every thing the holder has a role on (about 5.5 KB per thing below, to every reader of the holder, whatever it syncs).
> Priority: normal
> Tags: sync, engine, keys

## Measured
Engine, commits packaged as `thing_cost::what_a_reader_costs` does: removing one of m writer members of H is one commit of 2.7 KB + 4.9 KB per remaining holder (12.5 KB at 2, 32.2 KB at 6); the rotation it forces on a thing X that H holds write on is 11.7 KB (`secrets.0` 5.0 KB) with X's roster its admin and H.

## The two costs
1. **Every box to every reader.** A rotation's boxes page (spec/crdt.md §8), and a commit applies only once every page is fetched, so each of m readers downloads m holders' boxes: a removal costs the network m squared. A node that does not rotate the thing opens one box per role. spec/requirements.md Generality steers large rosters to nesting, which cuts m per level and leaves the top level's rotation to every member.
2. **Every box of everything below.** `Engine::key_part` (core/engine/src/sync_ids/certs.rs) puts under H's sync ID each held `secrets.0` part on X that boxes a secret to H, whole (every box of X), and X's `sync.0` parts (spec/permissions.md §4 Key part: H's edge piece on X). So each removal from H, which makes every thing below H rotate, sends every reader of H a copy of each of those rotations' boxes. A reader of X takes its box to H from X's own rotation commit; only a node entering X for the first time needs the copy, and only the boxes to H.

## Directions
- A copy under the holder's sync ID cut to the boxes to that holder, fetched for the things a node enters (notes/holder-access-study.md, the edge piece).
- A node that may not rotate a thing applies its rotation with the pages holding boxes it opens (unfetched pages are a may-hold state already, spec/sync-judgement.md §2); what a rotator, a re-sealer and the stale-box rules read of the other boxes decides how far this goes.
Both are design work with a model first. The first is decided as part of holding holders for keys (notes/holder-access-study.md, The direction: own boxes only) and owed by the sync rewrite (notes/sync-rewrite-state.md, Next); its cost at large rosters depends on both.
