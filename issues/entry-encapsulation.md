# An entry pays a second encapsulation beside its holder's box
> Summary: each entry's W is its own hybrid seal (about 1.1 KB) to the KEM key the holder's box in the same commit is sealed to; sharing the box's encapsulation does not fit as boxes are built, since the box sits inside the encrypted role section and boxes travel where no entry does; options below.
> Priority: normal
> Tags: sync, keys, performance

A read holder's read and sync entries are two hybrid seals (spec/wire.md §5 Entry blocks), 1,233 B each, beside its boxes (spec/crypto.md §4). Deriving W's key from the box's encapsulated secret needs the holder to reach that encapsulation before it opens the commit, and it cannot:
- **The box is in the encrypted body**: `secrets.0` pieces sit in the role section, under a roles secret of the epoch the commit is wrapped under, which a new grantee lacks (the read entry exists to give it that section's key).
- **The box cannot take the entry's encapsulation instead**: an entry belongs to one encryption, a box to the delta. Boxes travel without entries: certificate copies to a stub's readers (b = 0), role compaction snapshots carrying boxes as state, sections copied verbatim into another node's fresh encryption. And entries are made at every fresh encryption by any reader (core/engine/src/sync_ids/blobs.rs `seal`), who never knows the box's KEM secret, so it cannot key a W from it.
- **The independent make has nothing to share**: the maker boxes its own admin symmetrically (no encapsulation), so its two entries' 2.4 KB are W's own seals.

Options:
- **Hoisted encapsulations**: every blob carrying a sealed box (body, copy, snapshot, verbatim section) carries its encapsulation in a clear table, the box in the delta keeping only its AEAD part bound to it by hash; encapsulation coins derived from the boxed secret (with a read roles secret, so a store holding sync secrets cannot recompute them) so a re-encrypting reader can recompute the KEM secret and key W from it. Joint boxes need their outer layers hoisted too. A redesign of box and blob formats.
- **One entry per holder**: one encapsulation to the holder's sync KEM key carries the sync payload, and the read payload is keyed from it and DH(claim key, the holder's read X25519 key). Saves one seal per read holder (an independent make's entries 4.9 to 2.6 KB), but the line between a node holding the holder's read secrets and one holding its sync secrets alone is then classical only: a quantum sync-only holder of M reads the roster.
- **Symmetric W where the writer holds the holder's secret** (the maker's own admin): no encapsulation and still post-quantum, but entries then come in two lengths, telling a store how many boxed holders the writer holds secrets of; padding each length apart only shrinks that leak.
- Keep two seals per read holder (today).

Tess: perf, after behaviour is right; then do whatever is simplest and best in the end, regardless of churn.
