# Live role-class bodies are kept for good: rotations grow every holder's store
> Summary: spec/commits.md §5 Kept while live keeps a live role-class delta for good, so each rotation's `secrets.0` boxes and history box and its `sync.0` step stay as bodies at every holder, beside the state (and a snapshot) that carries them too. Replaced role-class bodies are compacted (keysets, removed holders' boxes, dropped claim sets); live ones never are, so storage grows per rotation, not with current state.
> Priority: normal
> Tags: retention, engine, keys, spec

Property: storage follows current state (notes/principles.md, storage attributable; spec/requirements.md Scale), and every drop but expiry and purge is a cover (spec/commits.md §5).

Measured: 30 rotations of every role of a thing with two holders leave about 30 more `secrets.0` and 30 more `sync.0` bodies at the admin and the reader (`keys.0` stays flat: `growth::rotations_keep_keysets_flat_*`). The state grows too (history boxes, steps), a separate matter (the history boxes row of the growth census, notes/growth.md); the bodies double it.

Why live role-class bodies are kept: certificate copies, evidence of a commit and stubs (spec/permissions.md §4) are cut from role commits' parts (a holder's `secrets.0` piece, the `sync.0` part recording a step), so a node must keep the commit's body to serve them. A snapshot already stands in where the spec allows it: evidence takes a `sync.0` snapshot recording a step (engine `evidence::a_write_listing_an_old_step_after_sync_is_compacted_requires_the_snapshot_*`), Established takes a `secrets.0` snapshot keying an epoch (spec/crypto.md §4), and a `secrets.0` snapshot is pieced per holder (spec/wire.md §4 Pieces), so a holder's copy could be its piece.

Options:
1. Copies, evidence and stubs cut from the newest valid snapshot where the commit's part dropped (a holder's piece and the rest, the steps a `sync.0` snapshot records); then drop the Kept while live rule for role-class (live parts drop under covers like content, past `ROLE_KEEP` of what?). Needs: what a stub is once its rotations' parts are gone (H's boxes live in X's snapshot pieces), and a keep bound for live role-class parts (a node offline across it must still find its boxes).
2. State it: role-class bodies grow per rotation and grant for good (notes/growth.md row as now).

Cover risk to weigh with option 1 (it exists for replaced parts now): a role-class snapshot whose writer is later removed by a removal not listing it turns invalid (spec/permissions.md §5.2, A cover is its writer's edit); the bodies dropped under it count as never received, and a live box only it carried is lost where no node still holds its body. Own covers are content snapshots only (spec/wire.md §4 field 14), so no demoter re-covers role-class writes.
