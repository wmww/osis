# Membership flows: what is approximate or missing
> Summary: Parts of the membership flows not done or done approximately in `osis-node` `flows/` and `rotation/`: label replacement, unit erasure on lost access, frontiers above `CHUNK_THRESHOLD`, contact cards, departures recomputed from the whole edge history and the key-actor `carries` test.
> Tags: permissions, sync, node

Repro: known gaps, no failing test; sim `label_replacement_offline` (tier 2) runs the replaced-label residue.

- **Label replacement** (spec/sync.md §2: admin rotation if needed, new index, re-upload, mark replaced, delete old content entries): node-sync's `replace_label` makes the next index, marks the old one replaced, and members follow (sim `label_replacement`); the admin rotation and the old label's maintenance are not done (issues/node-sync-gaps.md, Replaced labels; sim `label_replacement_offline`).
- **Erasure on lost access** (spec/permissions.md §3): `Engine::drop_lost_secrets` drops the secrets of actors the node lost read on (diagnostic `Removed`), but not the local aspect units and commit records it can no longer read (issues/lost-access-erasure.md).
- **Frontier size**: a demotion's frontier goes inline in the header; above `CHUNK_THRESHOLD` it must be a chunked large value by link (spec/commits.md §1). `Mutation::frontier` takes a value only.
- **Contact card**: built in the osis API (`contact_card`: profile thing with its own label, the person's `/created` and `/keys` placed there as certificates, a read link to it); flows has no call of its own. `create_link` places L's card (its creation commit) under K's label so redeemers and verifiers of L's commits hold L's `/created`.
- **Departures** are recomputed on each call from the timeline and the `/secrets` state, recursively through member and owner actors: O(edge history + boxes) per `ensure_rotated`, and `introduced_by` scans `Core::box_keys`. Cache per actor, invalidated on roster and `/secrets` changes, if it shows in profiles.
- **Key-actor `carries`** (re-seal trigger): a key actor's box keyed at a higher role counts for a lower role's epoch when its commit is ordered at or after the commit that first boxed that epoch; otherwise a re-seal is made (a box of cost, never a leak).
