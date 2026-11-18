# Storage must not grow with writes or thing churn
> Summary: Tess's rule (spec/requirements.md Scale): neither repeated writes of any kind where history is not kept, nor making and releasing things again and again, grows storage without bound; a sensible configuration writes constantly for 20 years. Replacing writes are flat and tested; set removals, role changes and some rows still grow. Fix, test, and raise to Tess only what cannot be fixed without a real trade-off.
> Priority: normal
> Tags: engine, crdt, perm, spec, tests

## The rule (Tess)
- Requirements that say otherwise are wrong and get fixed; code that does not meet it is wrong and gets fixed; it is tested as far as reasonable (count stored bytes at n and 10n writes, notes/principles.md Check scaling).
- What cannot be fixed, or only with a significant trade-off, goes to Tess with the trade-off stated. Nothing else needs her.
- Purging is a different matter: this is about replacing writes and released things.

## Flat today
Replacing writes once covered (osis-sync `growth::*_grow_nothing_spec_commits_5`, the S1 arms). `growth::flat` (6 vs 60 more writes) allows a store's attribution rows (`B/`, `W/`) at most one per entry, 64 B for a counter that widened, and does not count pages (their layout follows the write history within a bound: check the bound is on live data).

## Grows today
- **Set removals**: a tombstone of a few bytes per removal in the roots' `holds.0` and `tickets.0` (`TOMBSTONE_BYTES`, issues/storage-owners.md 12), so making and releasing things grows them for good; the same for any set an app adds to and removes from. Stated reason: no cover can drop one without losing a removal's finality. This is thing churn, so it breaks the rule: find the design that drops them (a likely trade-off to raise, with "No horizon ever drops an edit").
- **Role changes**: spec/requirements.md Scale keeps a thing's permission history whole, a few hundred bytes per change, fetched and checked by every new holder. Repeated grants and removals are repeated writes. Fix or raise.
- **Rows S1 allows**: schemas a node learned (`d/`), `cv/` at most one row per held snapshot: bounded by what, and is that bound live data?
- **Account names** at rotations (issues/rotation-names-grow.md), and whatever replaces them (issues/actors-one-mechanism.md: nothing kept per commit for good).
- **Usage rules that exist to dodge growth** (spec/requirements.md Scale: commit per editing pause, never per keystroke; presence by expiring ephemeral writes): if growth is fixed they are advice on cost, not on what fills a disk; reword or drop.

## Work, not storage
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again at each later own replace of its covered aspects (spec/commits.md §5 Own replaces): work per write grows with such commits held.
- A snapshot rewrites the whole field, so each compaction of a very large field writes and logs it whole (no snapshot links existing pages).
