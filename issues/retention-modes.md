# Retention: what is left of the history-modes work
> Summary: Open items of the retention work: the order-oracle redesign, the ephemeral map-key question, the swept hidden write; Tess's standing decisions on naming, the purge-on-replace fallback and small values.
> Priority: normal
> Tags: engine, spec, retention

Design: spec/commits.md §5-§7, notes/engine-retention.md. Model findings: core/test/held-model/AMBIGUITIES.md (held-model-4, thing-level history).

## Left
- The order oracle's redesign (notes/test-design.md).
- **Ephemeral (open)**: an expiring delta is covered by the join like any body, which does not replace spec/sync.md §9 Superseded parts: a map key's rewrite (`KeepAlive`, a cursor map) is a `Put`, a fresh entry, and the old entry stays live in the CRDT (shadowed only in the read), so no cover drops it; without the rule a cursor holds every move to its expiry (measured: 60 moves, 60 commits and host entries, against 1). Options: keep the rule and its second session; a move that removes the old entry (dead, so covered), at a map tombstone per move held in every holder's state; a crdt change (a put that replaces the key's own entries). notes/ephemeral.md Divergences left; issues/connection-lived-data.md.
- issues/swept-hidden-write-uncoverable.md.

## Decided (Tess)
- **Names.** "No history needed" is the default, never the delete-on-change option: an entry with no `history` promises nothing; `keep` is named for keeping; the delete-on-change option is named for what it does (`purge_on_replace`) and documented as rarely right because it costs more per change. Public docs never mention compaction.
- **Fallback for purge on replace.** If compaction on replace causes problems: replaced writes become `writer` purgeable and the writer attaches a purge request for them to each edit, generated automatically. Known costs: a purge cannot express a partial replacement of a body, a purge request is kept to its floor (`ROLE_KEEP`), purged writes leave leftovers. Acceptable as a fallback.
- **Small values.** Per-commit overhead matters less than extra mechanisms. Do: forget compacted headers when nothing needs them (issues/session-sources.md, notes/growth.md row 1). Maybe: a whole replacement covering the old body directly, only if cheap. Don't: special commit forms for small durable writes.

## Definitions the code follows
- **Replaced** is "the body holds a write the canonical state does not hold" (what a snapshot from the state leaves out), not "has a dead write" (spec/crdt.md §4.8): a root reset is dead once a later write implies one, yet canonical form keeps it, so by deaths every cover of such an aspect is replaced for good and covers chase each other.
- **Covered-equal** snapshots at one `ts`: only the lower commit ID covers (spec/sync.md §7), else two covers drop each other.
- A local drop as covered needs no right of the dropping node (the snapshot's commit holds it).
