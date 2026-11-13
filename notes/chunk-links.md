# Links carry what deleting their blob needs
> Summary: Why no header or snapshot lists the blobs a commit links: every LINK carries its blob's prefix salt and delete keys (Del), so whoever holds a link deletes the piece. Principle, reuse, the freed judgment's shape, what replaced each list use, security per attack class, rejected alternatives. Code detail: notes/engine-paged.md (Freed sets).

Tess's goals: no size cap from lists, small snapshots, one mechanism; a node that cannot read learns no tree shape (which pieces belong to which commit, which pieces edits share).

## Principle
A link is the whole authority to read and to delete its blob: whoever holds the link and knows its thing computes the blob's commitments (link blind, thing blind) and, with the delete key of a level, signs its delete. A piece goes once no held body or live state of its thing links it (`Core::tree_refs`). The storing node checks each delete against the prefix.

## The link
- `LINK := [content hash, blob ID, suite || key, salt, [DeleteKey*]]` (spec/data-model.md §5, §6) everywhere a LINK stands: value roots, tree-node children, page links, link pages, header lists, a linked frontier, a `ThingList`.
- Del is the keys of the blob's one commitment group, by level ascending (empty for a `nobody` delta's blob). It is the writer's claim, never authority: a holder of the blob checks it against the prefix before using it (reuse, deleting by the label key, dropping its copy); a node not holding the blob deletes by level only and the host checks.
- Derived, not carried: link blind (`kdf("link blind", blob key)`), thing blind (link blind and the tid of the source being walked). Not carried: expiry and class (a deleter needs neither).
- The salt is carried so a holder of a tree's interior nodes deletes every leaf without fetching any chunk (deleting a dropped 1 GB value needs its node blobs, about 0.3% of its bytes). Deriving it from the key instead: issues/link-salt-from-key.md.
- Cost: a link encodes in 125 B with no Del, 233 B with three keys (`cbor::link_len`); a `[Link+]` reaches `PAGE_TARGET` at 280 to 520 links. Link depth: 3 levels (4 with keys), counted by tree-node and value depth limits.

## Reuse
- A reused piece keeps its blob, prefix and commitments: the new parent copies the old link verbatim, Del and salt included. Nothing is listed anywhere else.
- When to re-encrypt stays spec/sync.md §1, judged on the held prefix; the reuser also re-encrypts a link whose Del the prefix does not bear. A piece not held is written afresh.
- Across authors the copied Del may name the first author's level-2 key beside the thing's level-1/3 keys; a deleter signs per group with whichever level it holds.

## The freed judgment
- A drop (cover, own replace, purge, expiry; not invalid: an invalid body stays at hosts as a refetch source) puts the body's links in a durable per-thing freed set, then drops the body.
- Each freed link is judged when its delete is sent, against the sources of its thing held then, never once at the drop (a body fetched again or a new reuse in between keeps the piece with no extra rule; held-model step 0 found this). Linked: kept. Else a node's links join the set (nodes are immutable, so the walk stops at shared nodes) and the piece is deleted at every host of the thing's labels holding an entry of it.
- A judgment needs every node blob on the way; one no copy of which is left blocks that thing's judgments at that node (`Trees::missing`). Deletes go in shuffled batches, no level order.
- A judged link keeps no key, so a dropped body's pieces are unopenable at once (spec/commits.md §5 Shredding).

## What replaced each list use
- **Fetch and memory gate**: by walking what a commit links (`apply/reach.rs`, `Engine::blob_wants`); the gate is staged (commit blob, pages, roots' claimed lengths), lengths are claims enforced as resolved (spec/wire.md §6).
- **Upload**: a body's walk (`Engine::body_links`).
- **Trigger** (spec/sync.md §7): a body weighs the tree its links free (a walk stopping at blobs a live state links); the estimate grows per join by what the unlinked trees hold beyond the linked ones (a level-aligned walk, flat in value size); a snapshot weighs its encoded state alone.
- **Repair** (spec/sync.md §1): `Engine::relink` asks each thing of the closures that lost a blob whether its live states link it (memoized tree walks; a rare path, no index).
- **Relay-only commits** never page (spec/commits.md §2): a delta linking a page is bad input (`verify::NoPages`).
- **Commit size**: no list bounds it; one commit blob (`MAX_BLOB`) does (issues/commit-size-below-requirement.md).

## Security, per attack class
- **Forged listing** (a writer of t1 copies t2's link into t1): under t1's tid the blob bears no commitment, so the host refuses a delete by level and a holder checks before using the label key. The judgment is per thing, so t1's link keeps nothing of t2 alive.
- **False Del**: deletes nothing (the host checks the prefix); a true one deletes only what no held source of the thing links at that node. The co-writer race is answered by repair.
- **Deleter lacking the tree**: deletes nothing until it holds the nodes. If every copy of a node is gone, its subtree stays until expiry or a label-key clear.
- **Removed reader**: deleting needs the current label key besides the delete key; lost access discards its freed set.
- **What a storing node learns**: per-piece deletes under their own salt and thing blind; no list whose length tracks how many blobs a commit introduced or a value links.
- **Cross-group**: a piece under G1 and G2 is one blob with one entry per label; a delete removes one entry and needs that label's key.

## Rejected
- **Parent/child refcount at the storing node**: the host would learn tree shape.
- **Delete keys in a per-node table**: a value's root link and a fragment's page links need the same data, so a second format or re-encrypting each root per snapshot.
- **Keys found by trial against the prefix**: a fetch per chunk and O(epochs) scalar multiplications per key set.
- **Bottom-up delete rounds**: round timing shows a host which blobs are interior. A durable freed set covers crashes.
- **Snapshots stop listing, deltas keep their list**: keeps a per-commit cap and two mechanisms.
- **Re-encrypting every reused piece**: O(value) per edit, ends reuse.

## Open
- With keys in every link, reuse could ask a level match rather than exact keys, so a thing's rotation stops re-encrypting every value at its next edit (not filed).
