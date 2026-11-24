# Storage must not grow with writes or thing churn
> Summary: Tess's rule (spec/requirements.md Scale): neither repeated writes where history is not kept nor making and releasing things grows storage without bound; a long-lived thing may grow modestly with the role changes made on it or on what its writers act through. Replacing writes are flat and tested. Set removals' tombstones still grow with churn, and a removal's list (frontier, addenda) stays with the removal for good, outliving the commits it names where history is kept.
> Priority: normal
> Tags: engine, crdt, perm, spec, tests

## The rule (Tess)
- spec/requirements.md Scale: a thing grows with role changes on it or on what its writers act through (evidence copies follow role churn on the edges its writers go through).
- Purge requests are listed in every removal of their author while held, and purge-carrying commits stay held, mostly for good (notes/growth.md): 32 B per request per removal, accepted.
- Requirements saying otherwise are wrong and get fixed; code not meeting it is wrong and gets fixed; tested by counting stored bytes at n and 10n writes. What cannot be fixed without a significant trade-off goes to Tess with the trade-off stated. Purging is a different matter.

Flat today: replacing writes once covered (osis-sync `growth::*_grow_nothing_spec_commits_5`; `growth::flat` allows a store's attribution rows one per entry and does not count pages: check their bound is on live data).

## Grows today
- **Set removals**: a tombstone per removal in any set added to and removed from (the roots' `holds.0` among them), so making and releasing things grows them for good. The tombstone is for a late-arriving older add from a node that held the add without the removal (spec/crdt.md §5.5 Tombstone lifetime): with today's merge rules only two of three hold (a removal is final, a node may return after any time offline, no growth with churn). First look for the design keeping all three: a writer whose counters survive restarts lets a node hold "seen everything of this writer up to n", so an absent element at or below n is known removed with no tombstone, and growth follows the number of writers. Today sources are sessions and commits, random and unlinkable, counters in memory only; check what durable counters cost (a crash must never reuse one). **If there is no good fix (Tess)**: loosen "a removed element never comes back": where history is kept the removal stays final (the option pays for it); elsewhere a set keeps tombstones in a buffer bounded by time and/or count (notes/arbitrary-values.md: at 0 no removal is final against a stale node; unbounded is today), and spec/requirements.md Data model states the weaker property.
- **Rows S1 allows**: schemas a node learned (`d/`), `cv/` one row per held snapshot: bounded by what, and is that bound live data?
- **Usage rules that exist to dodge growth** (commit per editing pause, never per keystroke; presence by expiring ephemeral writes), stated in spec/requirements.md Generality: once growth is fixed, check they are no longer needed.
- **A removal's list outlives the commits it names** (below).

## A removal's list
A removal's list (frontier content, purge-request and role entries; addenda of each witness) is inside the removal, whole in every copy (notes/write-path-design.md §2, E4), bounded per removal by what the remover then held of the removed party. With no history promised that is O(live state) (the uncovered backlog, which the compaction trigger bounds); with history kept, every commit the history held, kept after the history it served is gone: a leak (notes/principles.md, Close leaks), open. What else names commits and how long it stays: notes/growth.md.

When an entry is dead: a verdict reads an entry naming commit c only when it judges c, and a node judges only commits it holds, so content and purge-request entries are dead at a node from when it forgets c until c comes back (a store keeping it unread, a peer that has not compacted); they must come back with c, or c's live write is lost there when the cover carrying it falls. Role entries name role commits, never forgotten: never dead. Globally dead is not knowable, so entries are dropped per node.

Proposals:
1. **An entry is evidence of the commit it names, and leaves with it**: content and purge-request entries in per-thing leaves a node holds while it holds a commit whose verdict reads the leaf; role entries stay with the removal. Modelled (over the old role rules): an entry travelling with its commit reads as the built rule everywhere; an entry gone for good once its commit is forgotten does not. Not the design: every carriage rule tried either let a removal arrive without the leaf its listed writes need (they pend for good) or kept every leaf with its removal for good. E4 allows a per-thing form back only under a carriage rule by which no holder of a removal can lack a part it could need.
2. Rejected: **a window** (list only commits stamped within a span before the removal): stamps are the removed party's own, so no span is justified (notes/arbitrary-values.md), and listing less buys nothing.
3. Rejected: **a later role commit compacting earlier lists**: two admins compacting differently give two readings (notes/principles.md, Forks are permanent).

## Left: work, not storage
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again at each later own replace of its covered aspects (spec/commits.md §5 Own replaces): work per write grows with such commits held.
- A snapshot rewrites the whole field, so each compaction of a very large field writes and logs it whole (no snapshot links existing pages).
