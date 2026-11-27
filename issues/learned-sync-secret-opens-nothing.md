# A learned sync secret opens nothing at a node holding no read secret
> Summary: `apply::keys::learn_secret_in` sets a sync secret learned from an entry box without opening the thing's history boxes when the node holds no read secret of it; a rebuild opens them, so live and rebuilt indexes can differ.
> Priority: low
> Tags: engine

`learn_secret_in` returns early for a sync secret where the node holds no read secret of the thing: it sets the secret and runs no `ingest_secrets`. A `secrets.0` history box under that sync epoch already held (taken by a notice's copy that boxes the public, before the node's role gave the secret) then stays unopened live, while an open from the store (`check_index`) opens it and gets the epoch's `supersedes` and names. Seen once on a full-size differential script (a removed reader told the public's edge by notices) while a departed peer's ByRole opened an ended member; with that path gone no test reaches it.

Fix: delete the early return, so a learned secret always opens what it opens (`ingest_secrets` judges by `may_take_role` as for any box). It passed osis-sync and engine; it needs a reproducer first: an engine test where a sync-only node takes such a history box by notice, then learns the epoch's secret from the public entry, then `check_index`.
