# Certificates are one whole set per thing
> Summary: `Engine::sync_certificates(g)` is one memo holding every certificate of g's sync IDs, read whole by every certificate-ish commit's bodies; under an actor's inbox it unions the grant copies of every thing the actor is named on, so any role-class change on any of those things recomputes it in O(things named on) and moves every such commit's bodies there.
> Priority: normal
> Tags: engine, sync, performance

- Measured: `facade::a_new_grant_copy_lists_in_proportion_to_change_spec_sync_inbox_5` (ignored, counts `sync: grant copies listed`): one new thing lists 6 copies at n = 3, 33 at n = 30.
- A memo reading memos inherits their reads (`memo::depend`), so a stable copy does not stop the union from recomputing; a tree of union memos still clones the whole set at the root.
- The whole-set shape predates grant copies (`certificate_authors`, chains into the closure); grant copies make it scale with what the account is named on rather than with g's closure.
- To weigh: certificate bodies asked per commit (which sync IDs name commit c as a certificate), from the commit's own aspects outward: an edge write names its (actor, thing) copy directly, a `sync.0` write the copies of the actors named on its thing; author chains need a reverse index (which (author, thing) chains a role commit is on). Records likewise per record.
