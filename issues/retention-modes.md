# Retention: three history modes
> Summary: Per-write history mode (no promise, keep at least, purge on replace) beside purgeable-by and expiry (Tess), built: every drop that is not expiry or purge is a right holder's covering compaction snapshot. Holds Tess's decisions on it and what is left: the order-oracle redesign, the ephemeral map-key question, the swept hidden write.
> Priority: normal
> Tags: engine, spec, retention

The steps cited from code and models: 0 the model (held-model, TLA sync; findings in core/test/held-model/AMBIGUITIES.md held-model-4), 1 the wire form, 2 purge on replace as the writer's cover, 3 no death dating, 4 state is the join of held bodies, 5 listings show only kept history. Design: spec/commits.md §5-§7, notes/engine-retention.md.

## Left
- The order oracle's redesign (notes/test-design.md).
- **Ephemeral (open)**: an expiring delta is covered by the join like any body, which does not replace spec/sync.md §9 Superseded parts: a map key's rewrite (`KeepAlive`, a cursor map) is a `Put`, a fresh entry, and the old entry stays live in the CRDT (shadowed only in the read), so no cover drops it; without the rule a cursor holds every move to its expiry (measured: 60 moves, 60 commits and host entries, against 1). Options: keep the rule and its second session; a move that removes the old entry (dead, so covered), at a map tombstone per move held in every holder's state; a crdt change (a put that replaces the key's own entries). notes/ephemeral.md Divergences left; issues/connection-lived-data.md.
- issues/swept-hidden-write-uncoverable.md.

## Decided (Tess)
- **Model.** The history value is purge on replace (gone once replaced) or keep at least until T for T in [0, ∞], and/or until D after replaced: 0 is no promise, ∞ kept forever. Keep is enforced only as a limit on compaction and covered drops and on what a listing shows. Expiry is the separate purge at T. A node without write drops nothing on its own but expired content.
- **Readers under keep-for-D.** One rule for every node: a body under keep-for-D is not dropped until D after the earliest valid replacing write the node holds (a function of the held set, not arrival order). Readers and writers holding the same data show the same history.
- **Names.** "No history needed" is the default, never the delete-on-change option: the default is unnamed; keep is named for keeping (`keep_history(forever)`, `keep_history(D)`); the delete-on-change mode is named for what it does (`purge_on_replace`) and documented as rarely right because it costs more per change. Public docs never mention compaction. `keep_history` until a past time or for 0 is the same as the default.
- **Fallback for purge on replace.** If compaction on replace causes problems: it becomes `writer` purgeable plus the writer attaching a purge request for the replaced writes to each edit, generated automatically. Known costs: a purge cannot express a partial replacement of a body, a purge request is kept to its floor (`ROLE_KEEP`), purged writes leave leftovers. Acceptable as a fallback.
- **Small values.** Per-commit overhead matters less than extra mechanisms. Do: forget compacted headers when nothing needs them (issues/session-sources.md, notes/growth.md row 1). Maybe: a whole replacement covering the old body directly, only if cheap. Don't: special commit forms for small durable writes.

## Definitions the code follows
- **Replaced** is "the body holds a write the canonical state does not hold" (what a snapshot from the state leaves out), not "has a dead write" (spec/crdt.md §4.8): a root reset is dead once a later write implies one, yet canonical form keeps it, so by deaths every cover of such an aspect is replaced for good and covers chase each other.
- **Covered-equal** snapshots at one `ts`: only the lower commit ID covers (spec/sync.md §7), else two covers drop each other.
- A snapshot is purge on replace when it carries such a write live.
- A local drop as covered needs no right of the dropping node (the snapshot's commit holds it).
