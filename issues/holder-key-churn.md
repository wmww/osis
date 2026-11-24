# A holder's readers download every box of it and of everything it holds
> Summary: Two costs no reader needs: every reader of a thing fetches every box of each of its rotations (a removal from m holders costs the network m squared), and a holder's sync ID carries the whole `secrets.0` part of every rotation of every thing the holder has a role on, to every reader of the holder.
> Priority: normal
> Tags: sync, engine, keys

Measured: notes/holder-access-study.md, Baseline.

1. **Every box to every reader.** A rotation's boxes page (spec/crdt.md §8), and a commit applies only once every page is fetched. Nesting (spec/requirements.md Generality) cuts m per level and leaves the top level's rotation to every member.
2. **Every box of everything below.** `Engine::key_part` (core/engine/src/sync_ids/certs.rs) puts under H's sync ID each held `secrets.0` part on X boxing a secret to H, whole, and X's `sync.0` parts (spec/permissions.md §4 Key part). Each removal from H makes every thing below rotate and sends every reader of H all those boxes; only a node entering X for the first time needs them, and only the boxes to H.

Directions (design work, model first):
- The copy under the holder's sync ID cut to the boxes to that holder, fetched for the things a node enters (notes/holder-access-study.md, The direction: own boxes only; owed by the sync rewrite, notes/sync-rewrite-state.md, Next).
- A node that may not rotate a thing applies its rotation with only the pages holding its boxes (unfetched pages are a may-hold state, spec/sync-judgement.md §2); what rotators, re-sealers and the stale-box rules read of the other boxes decides how far this goes.
