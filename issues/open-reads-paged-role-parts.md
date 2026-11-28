# An open reads the blobs of paged role parts
> Summary: opening the store decodes held role commits' parts (`apply::load`, the open's sweep), and a role part paged into page blobs (a large `keys.0` or `secrets.0`: many boxes, a keyset with KEM keys under small pages) is read from its blobs, where the index check wants an open from the persisted index to read none (`Engine::checked_index`: "opened from the persisted index: N blob reads"). `apply::tests_paged::a_fill_goes_on_past_failed_writes_and_reloads_*` reaches it under its tiny test pages once every test peer's node thing names an inbox.
> Priority: normal
> Tags: engine

Reached: under `apply::tests_paged::small_pages`, each peer's node thing (its `keys.0` naming its inbox) and its inbox (a minted independent thing with boxes to it) hold role parts past a page; the index check's non-rebuild open decodes them (`apply::held_parts_at` from the load) and reads 44 blobs. On origin/main without the harness inbox the same test reads none: its role parts fit inline. The same holds for any node whose role state outgrows a page at the production page size (an account boxing many holders).

Either the open keeps what it reads of role parts in rows (as `node/perm` keeps edge parts), so a paged role part needs no blob at open, or the check's rule is wrong and an open may read the pages of the role parts it derives from (stated, with its cost).
