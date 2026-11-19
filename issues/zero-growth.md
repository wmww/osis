# Storage must not grow with writes or thing churn
> Summary: Tess's rule (spec/requirements.md Scale): neither repeated writes of any kind where history is not kept, nor making and releasing things again and again, grows storage without bound; a sensible configuration writes constantly for 20 years. Replacing writes are flat and tested; set removals and some rows still grow. Modest growth of a long-lived thing with its role changes is accepted. Fix, test, and raise to Tess only what cannot be fixed without a real trade-off.
> Priority: normal
> Tags: engine, crdt, perm, spec, tests

## The rule (Tess)
- Requirements that say otherwise are wrong and get fixed; code that does not meet it is wrong and gets fixed; it is tested as far as reasonable (count stored bytes at n and 10n writes, notes/principles.md Check scaling).
- What cannot be fixed, or only with a significant trade-off, goes to Tess with the trade-off stated. Nothing else needs her.
- Purging is a different matter: this is about replacing writes and released things.
- Accepted (Tess): a long-lived thing growing modestly in proportion to the role changes made on it.

## Flat today
Replacing writes once covered (osis-sync `growth::*_grow_nothing_spec_commits_5`, the S1 arms). `growth::flat` (6 vs 60 more writes) allows a store's attribution rows (`B/`, `W/`) at most one per entry, 64 B for a counter that widened, and does not count pages (their layout follows the write history within a bound: check the bound is on live data).

## Grows today
- **Set removals**: a tombstone of a few bytes per removal in the roots' `holds.0` and `tickets.0` (`TOMBSTONE_BYTES`, issues/storage-owners.md 12), so making and releasing things grows them for good; the same for any set an app adds to and removes from. Stated reason: no cover can drop one without losing a removal's finality. This is thing churn, so it breaks the rule. The tombstone is not there for late edits (an edit names its entry and has nothing to apply to once the entry is gone) but for a late-arriving older add: a node that still holds the removed element hands it on, and without the tombstone the receiver cannot tell "never seen" from "seen and removed" (spec/crdt.md §5.5 Tombstone lifetime). So with the merge rules as they are, only two of three hold: a removal is final, a node may return after any time offline, storage does not grow with churn. Look first for the design that keeps all three: a writer whose counters survive restarts lets a node hold "seen everything of this writer up to n", so an element at or below n that is absent is known removed with no tombstone, and growth follows the number of writers (Tess accepts growth with role changes); with visible signers each node is such a writer (issues/actors-one-mechanism.md, sessions). If that fails, bring Tess the choice between tombstones for good and a horizon after which a long-offline node's old elements are refused, with figures.
- **Rows S1 allows**: schemas a node learned (`d/`), `cv/` at most one row per held snapshot: bounded by what, and is that bound live data?
- **Account names** at rotations (issues/rotation-names-grow.md), and whatever replaces them (issues/actors-one-mechanism.md: nothing kept per commit for good).
- **Usage rules that exist to dodge growth** (commit per editing pause, never per keystroke; presence by expiring ephemeral writes) are stated in spec/requirements.md Generality as steering toward lower cost: once growth is fixed, check they are no longer needed to keep a disk from filling.

## Work, not storage
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again at each later own replace of its covered aspects (spec/commits.md §5 Own replaces): work per write grows with such commits held.
- A snapshot rewrites the whole field, so each compaction of a very large field writes and logs it whole (no snapshot links existing pages).
