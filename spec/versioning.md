# Versioning
> Summary: The format version and the other extension points, the parking rule for data a node cannot interpret, schema identity in commit headers, the additive evolution rules a schema must follow, open structs, reader defaults and typed-read failures.

## 1. Extension points
Four independent extension points, each parked separately so a node with one unknown item still reads everything else:
- **Format version**: one integer covering commit header fields, blob framing and format constants (`MAX_BLOB`, `CHUNK_THRESHOLD`, chunking and paging parameters, `MAX_DRIFT`). Readers MUST accept every older version forever. Writers MUST emit the oldest version that can express the commit.
- **Merge encodings**: IDs named per fragment inside a delta (spec/crdt.md §3.1). A change to an encoding's grammar is a new encoding ID with an embedding from the old one (spec/crdt.md §7), never an in-place change.
- **Value types**: new CBOR tags (spec/data-model.md §5).
- **Algorithms**: enum cases on keys, signatures and sealed boxes; suite bytes and suite IDs (spec/crypto.md §8).
Local storage, indexes, the node-to-node protocol (spec/sync.md §6, which negotiates its own version) and the API are not part of the format and change freely.

## 2. Parking rule
- A node MUST NOT discard, reject or crash on data it cannot interpret: an unknown format version, encoding ID, tag, field ID, enum case, AK, algorithm case or suite. It stores and relays the data, joins what it can, treats the rest as not yet received, and re-examines it after an upgrade.
- A parked delta is kept as bytes with its header entry. A parked commit is pending (spec/commits.md §4).
- A node MUST NOT compact away bodies it could not join; it accepts snapshots and retires of such blobs from other nodes like a blind node does.
- A membership-class value the node cannot type (an unknown role case, say) counts as not received; what depends on it stays pending.
- Malformed data (non-canonical bytes, out-of-range indices, a violated grammar rule) is bad input and MUST be rejected, never parked.

## 3. Schema identity
- Each AK belongs to exactly one schema. Only that schema extends the AK's type closure or allocates IDs under it.
- A commit header carries a **schema table** `[(schema ID, revision)]` and, per delta, an index into it, or none for an untyped write (spec/commits.md §1).
- A reader whose schema claims an AK and sees a delta on it under a different schema ID reports a namespace collision diagnostic. Merge is unaffected: the writes merge like any concurrent writes (spec/crdt.md §7).

## 4. Evolution rules
A published revision MUST be an additive superset of every earlier one. Relative to the last published revision, a new revision MUST NOT:
- reuse a field or case ID, or remove an item whose ID is not then reserved;
- change the type of an existing ID, or change an encoding except along a register embedding edge (`T` to `counter<T>`, `max<T>`, `min<T>`; `string` to `text`; spec/crdt.md §7);
- add a field without a default to an existing struct;
- change or remove a default, or add one to a formerly required field unless explicitly marked;
- change the schema ID, or publish without bumping the revision.
An aspect's wire type never changes; a different type is a new AK. Enum cases are never removed.

## 5. Reads and writes across revisions
- **Open structs**: state may hold field IDs a schema does not know. They are preserved, joined and ignored by typed reads.
- Writes are validated against the writer's schema; every field the writer's schema declares is required at write time.
- **Reader defaults**: a field with a declared constant default reads as the default when absent. A default is never materialized: the structural diff writes nothing for an absent field whose new value equals its default (spec/crdt.md §9).
- A typed read MUST fail, with the path, on an unknown enum case, a type mismatch or a missing field without default. Typed reads are also available per path. Untyped reads of any stored data always succeed.
- A writer never removes or rewrites data its schema cannot read, except by an explicit replace (spec/crdt.md §9).
