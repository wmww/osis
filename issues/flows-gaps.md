# Membership flows: what is approximate or missing
> Summary: Parts of plans/membership-flows.md not done or done approximately in `osis-node` `flows/` and `rotation/`: label replacement, unit erasure on lost access, frontiers above `CHUNK_THRESHOLD`, contact cards, departures recomputed from the whole edge history, the key-actor `carries` test, and delivery steps left to node-sync.
> Tags: permissions, sync, node

- **Label replacement** (spec/sync.md §2: admin rotation if needed, new index, re-upload, mark replaced, delete old content entries): not implemented. `labels::new_label` already takes the next index; the rest needs node-sync's upload and delete paths.
- **Erasure on lost access** (spec/permissions.md §3): `Engine::drop_lost_secrets` drops the secrets of actors the node lost read on (diagnostic `Removed`), but not the local aspect units and commit records it can no longer read; needs a node-core "forget thing" (store units, commit records, indexes).
- **Frontier size**: a demotion's frontier goes inline in the header; above `CHUNK_THRESHOLD` it must be a chunked large value by link (spec/commits.md §1). `Mutation::frontier` takes a value only.
- **Contact card** (spec/sync.md §3: a read link to a profile thing holding `/keys` and certificates): not built; `create_link` with a profile thing as target is most of it.
- **Departures** are recomputed from the timeline on each call (every applied lowering edge write, edges past `until`, recursively through member and owner actors): O(edge history) per `ensure_rotated`. Cache per actor, invalidated on roster events, if it shows in profiles.
- **Key-actor `carries`** (re-seal trigger): a key actor's box keyed at a higher role counts for a lower role's epoch when its commit is ordered at or after the commit that first boxed that epoch; otherwise a re-seal is made (a box of cost, never a leak).
- **Cascade trigger**: rotations below a departure are made by `Engine::ensure_rotated`, which labeling must call before wrapping, stamping or boxing under an actor (and `rotate_eagerly` for the eager option); nothing in node-core calls it.
- **Delivery**: flows return `Delivery` values (inbox blobs, direct sends, first placements, certificate copies, deposits); node-sync carries them out. A removal's `First` placement lists things, not labels; node-sync maps them to every label it tracks of each.
- **Recovery and redemption** assume the home label or K's label was claimed by static entry and downloaded first (node-sync), with `hold_key_actor` called before so the key's boxes open.
