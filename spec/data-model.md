# Data model and value encoding
> Summary: The data everything else carries: things, tids, aspects, types, canonical value encoding, large values, hashing, references (strong, weak, ticket), `holds.0` and tags, core aspects and schemas.

## 1. Things and tids
- Every datum is an **aspect** of a **thing**. A thing holds aspects and nothing else.
- A **tid** is 120 bits: the first 120 bits of BLAKE3 over the canonical encoding of the thing's **creation record** (spec/wire.md §3). Text form: 20 characters of unpadded base64url, prefixed `osis://` where ambiguous or user-visible.
- Creation record of a thing: (mint admin's tid, 32-byte random nonce) (spec/permissions.md §1), with a `link` field naming the target on a link's actor K (spec/permissions.md §7) and an `expires` field on a thing that expires (spec/commits.md §5 Destruction). Of a **key actor** (account, node, link key), which holds admin on itself: (algorithm-tagged signing public key, 32-byte nonce), with an `account` flag on an account (spec/permissions.md §1). A link key's nonce derives from its seed (spec/crypto.md §3).
- A node checks a creation record by hashing when it receives the thing's data.
- A tid is never a value: a value names a thing only by a reference (§8), which may dangle, and the thing may lack the expected aspects.
- A received record that hashes to a tid the node already holds a different record for is bad input: keep the held record, ignore the new one, report a diagnostic. Never panic on it.
- A thing never changes its record (its mint admin is history; its admins change by grants).
- A thing is made by a durable commit carrying its `created.0` (spec/commits.md §2); no ephemeral commit carries a record. Ephemeral writes (§2) are on things already made.

## 2. Aspects
- An aspect is identified by (tid, AK). An **AK** is a string (text on the wire) of the grammar `ak = [":" tid ":"] name *(":" name) (["+"] ["^"] ("." / "~") / "@~") version`, `name = [a-z_][a-z0-9_]*`, `tid` its 20-character text form (§1), `version` a decimal u64 without leading zeros: `name.0`, `contact:names.0`, `:<tid>:foo+^.1`, `call:ring+~0`, `call:knock@~0`. Anything else, or longer than the AK limit (spec/wire.md §4), is not an AK.
- The tid and name segments name the aspect; the **version** is its major version. A key with the same tid and name segments and a higher version is a **successor** of the lower: the form a breaking change takes (spec/versioning.md §4). A node may use the relation without any schema; it implies no conversion.
- **Markers**, alike for every AK, declared by a schema or not; `+`, `^` and `~` are independent of each other:
  - `+` **ephemeral**: writes of the aspect are held in memory by the nodes holding the thing, never in a durable commit (they sync as ephemeral commits, spec/commits.md §2, spec/sync-compaction.md §2). Without it, writes go in durable commits.
  - `^` **admin-only**: a write of the aspect needs admin on the thing (spec/permissions.md §5.2).
  - `~` in place of the `.` **signal**: the aspect has no current value. A write of it, a **fire**, is one whole-value set, never joined into state; the aspect always reads absent. An API keeps the two kinds apart: a signal is only fired and a value aspect only written; where a key's kind is not known until run time, a write of the other kind is refused before anything applies, and a read of the other kind finds nothing.
  - `@` before the `~` **external**: where the thing's current setting enables the signal (spec/commits.md §5 The setting), anyone holding the thing's public key record may fire it; elsewhere only its writers may (spec/sync-inbox.md §2, spec/permissions.md §5.2 External fires). It stands only before `~`, and never beside `^` or `+`.
  - An ephemeral signal (`+` and `~`) is delivered here and on the nodes connected now, and held by none (relay-only commits, spec/sync-compaction.md §2). Listeners hear each fire once where it is fired and once where it is delivered, as its commit as written; no listing shows it.
  - A signal without `+` is written in durable commits: each write is history from the moment it is written, kept at least as long as its thing's setting keeps it (spec/commits.md §5 The setting), never joined, and heard by listeners as a listed commit. An author may replace its fire with a later whole value (spec/commits.md §5 Signals).
  - A node decides an aspect's storage class from its AK alone (spec/commits.md §2).
  - Ephemeral writes carry no retention; expiry applies (spec/crdt.md §4.7, in memory).
  - Core aspects are durable. None is a signal but an inbox's two (§9).
- AKs of one name segment and no tid belong to the core schema (§9); no other schema declares one. Every other AK has two or more name segments or a tid segment: first-party AKs live in the osis repository (`contact:names.0`); an app's start with a tid its maker administers, by convention (nothing checks it).
- An aspect is present iff its root fragment is present (spec/crdt.md §4.3).
- A schema declares per AK: the type, the default purgeable-by (`admin`, `author_or_admin` or `writer`, spec/commits.md §5; `admin` unless declared), which the writer puts into every delta, an optional default expiry duration measured from the write (spec/commits.md §6), and flags `synthetic`, `guaranteed`, which are local: nothing on the wire enforces them. What history keeps is no schema's: it is each thing's setting (`retention^.0`). An ephemeral AK declares no purgeable-by, an ephemeral signal neither that nor expiry.
- A schema declares at most one AK per tid segment, name segments and version: keys differing only in markers are not both declared. Changing an aspect's markers takes a new version.

## 3. Types
- Scalars: `string` (UTF-8), `blob` (bytes), `bool`, `int` (i64), `float` (f64).
- References (§8): `strong`, `weak`, `ticket`, and `ref`: a strong or a weak, the writer choosing per value. No type, encoding or API gives a reference a default kind.
- `enum { id case, id case(T), ... }`: cases with explicit non-negative integer IDs and optional payload type.
- `struct { id field: T, ... }`: fields with explicit non-negative integer IDs and an optional constant default.
- `list<T>`, `map<K, V>`, `set<T>`: any type as element, key or value.
- **Encoding wrappers** change only how concurrent writes merge; reads and writes see the inner type: `counter<int|float>` (sum of contributions), `max<int|float>`, `min<int|float>` (extreme of contributions), `text` (a string merged as a sequence). Every other type has one encoding (spec/crdt.md §3.1).
- Named types may take parameters and may be recursive. Standard named types:
  - `option<T>` = `enum { none 0, some 1 (T) }`, default `none`.
  - `markdown` = `text`, content not guaranteed valid.
  - `timestamp` = `int`, milliseconds since the Unix epoch, UTC. `duration` = `int`, milliseconds.
  - `date` = `int`, days since 1970-01-01 in the proleptic Gregorian calendar: a civil day, no zone.
  - `localtime` = `int`, milliseconds since 1970-01-01T00:00 of an unnamed zone, no leap seconds: a wall-clock time. With an IANA zone name it resolves to an instant at read time under the reader's zone rules; a wall time inside a gap (clocks moved forward) resolves forward by the gap, one inside an overlap (clocks moved back) to the earlier instant.
  - `any`: the raw canonical value, self-describing by its CBOR encoding (§5); a map with int keys reads as `map<int, any>`, so a struct held in an `any` position reads back as a map.
- Field and case IDs are never reused (spec/versioning.md).
- Encoding wrappers are not allowed as set elements or map keys (those are atomic).

## 4. Values
- A value is a finite tree; never cyclic.
- Struct fields, enum payloads, map values and list elements are mergeable positions (spec/crdt.md). **Set elements and map keys are atomic**: identified by their whole value, compared by canonical bytes (large values: by keyed content hash, §6).
- Absence is expressed by `option<T>` or by a missing struct field, never by a null.

## 5. Canonical CBOR profile
Values are CBOR (RFC 8949) restricted to the following profile. A decoder MUST reject anything outside it, so canonical bytes are hashed and stored as received, never re-encoded.

| osis | CBOR |
|---|---|
| string | text string (major 3) |
| blob | byte string (major 2) |
| bool | simple 20/21 |
| int | major 0/1; values outside i64 rejected |
| float | always 8-byte float (0xfb) |
| list | array (major 4) |
| map | map (major 5), keys sorted by their canonical encoded bytes (bytewise lexicographic) |
| struct | map with int keys (field IDs); unknown IDs preserved |
| set | tag 258 around an array sorted by canonical encoded bytes of the elements |
| strong | tag 1620 (STRONG) around the target's tid, a 15-byte byte string |
| weak | tag 1621 (WEAK) around the target's tid, a 15-byte byte string |
| ticket | tag 1622 (TICKET) around `[target, sync_id, role, epoch, box, holder, profile]` (§8) |
| enum | tag 1617 (ENUM) around `[case_id]` or `[case_id, payload]`; `case_id` a major-0 integer at most 2^63 - 1 |
| link | tag 1618 (LINK) around `[content hash, blob ID, suite byte || key, salt, [[level, pk]*]]` (§6) |

- Tag numbers ENUM = 1617, LINK = 1618, STRONG = 1620, WEAK = 1621, TICKET = 1622 (unassigned in the IANA CBOR tags registry); 1619 (STRUCT) is reserved, unused; 1616 is retired, never reused: a decoder rejects it. Each encodes as `0xd9` plus two big-endian bytes.
- RFC 8949 §4.2.1 core deterministic rules: shortest integer and length heads, definite lengths only, sorted map keys, no duplicate keys. Deviation: floats are always 8 bytes, so a float's bytes are its bit pattern.
- A set with two elements, or a map with two keys, that are equal under §4 and §6 (distinct bytes, links of one content hash) is rejected.
- No `null`, `undefined` or simple values other than true and false.
- Depth: a value nests at most 64 arrays, maps and tags deep as read; writers refuse deeper values, decoders reject them. A link (§6) counts as the value it reads as: a decoder counts it as a leaf, and a read of it at a position `d` levels deep reads it within `64 − d` levels (deeper: a link it cannot read, §6). Decoder limits for every other object: spec/wire.md §12.
- Floats: value identity is the IEEE 754 bit pattern. NaN is normalized at construction to the positive quiet NaN with zero payload; a decoder rejects any other NaN. -0.0 and 0.0 are distinct.
- Unknown tags are not errors: the value keeps the tag and its content as raw canonical bytes, merges as an opaque register value and fails only a typed read. New osis types are added as new tags (spec/versioning.md).
- Names never go on the wire; struct fields and enum cases are integer IDs. A struct and a `map<int, T>` share an encoding; the schema decides.

## 6. Large atomic values
- A blob, a string in register encoding, or a set element or map key whose canonical encoding exceeds `CHUNK_THRESHOLD` (format constant, spec/wire.md §2) MUST be chunked; one at or below it MUST NOT be. Durable and ephemeral content alike (an ephemeral commit's chunks are ephemeral blobs, spec/wire.md §5):
  - A role-class aspect's values (§9) stay inline, whatever their size (a `sync.0` claim set, a `secrets.0` history box).
  - A delta on any other aspect holding such a value unchunked is bad by itself (spec/commits.md §4), judged without its type: a `Str` or `Bytes` in a register value, a set or bag element's whole value, a map key.
- Chunking: content-defined boundaries over the canonical bytes, chunker of spec/wire.md §6, giving a tree: leaves are chunks, interior nodes hold links with the plaintext length under each; the value's place in the enclosing CBOR holds the root link. Chunker, tree shape and node layout: spec/wire.md §6.
- Every chunk and interior node is a separate blob encrypted under a fresh random key (spec/sync-ids.md §1). A **link** = (keyed content hash of the subtree, blob ID, suite byte || 32-byte blob key, the blob's 16-byte prefix salt, its delete keys: `[level, pk]` pairs, levels 1 to 3 strictly ascending, `pk` 32 bytes) (spec/crypto.md §6, §7): what reads the blob and what deletes it. A decoder rejects any other shape (as tag content); a link's salt and delete keys are its writer's claim, never checked when reading; the root's content hash is a function of the value's canonical bytes alone (spec/wire.md §6).
- Equality of a large value is equality of its keyed content hash, never of its link bytes.
- A link stands only where the type takes one: a blob, string or `any` position, or a set element or map key (or a position inside one) whose type is not **small**.
  - Small types can never exceed `CHUNK_THRESHOLD`: `bool`, `int`, `float`, `strong`, `weak`, `ref`, `ticket`, counter, max, min, and an enum whose cases carry no payload.
  - A link anywhere else is a type mismatch (spec/versioning.md §5): a typed read reports it without fetching the link.
  - In a core aspect (§9) it is bad input (spec/crdt.md §3.3 rule 7).
- A read that materializes a link it cannot read (a blob of its tree not held, which includes a blob ID nothing holds, failing to decrypt or verify under the thing's dedup secret, spec/crypto.md §6, or a value nesting deeper than its position leaves room for, §5) MUST fail only that position: the link reads as absent (its list or set element, its map entry or struct field, and an enum whose payload it is, read as absent; at the aspect root the aspect reads absent), the rest of the value reads, and the node reports a diagnostic.
  - Every read of the value (typed, untyped, per path, watches) applies this rule alike.
  - A read of one commit's body (a listed part) holding such a link reads that body whole as not fetched.
  - When a blob such a read lacked arrives, the node delivers the aspect, or that commit, to its watches again.
- A reference inside a chunked set element or map key counts as any other (§8 What counts): it is seen once the node holds the chunks of the element, and until then not at all.
- Every blob is at most `MAX_BLOB` bytes (format constant, spec/wire.md §2); a commit's limit is its header lists' (spec/commits.md §1). A revoke frontier (spec/permissions.md §5) above `CHUNK_THRESHOLD` is chunked the same way and referenced by link.

## 7. Hashing
- **Keyed content hashes** (delta hashes, link content hashes) are keyed BLAKE3 under the thing's **dedup secret** (spec/crypto.md §6), so only readers can compute or confirm them.
- Unkeyed BLAKE3: tids (over creation records), commit IDs (over headers), blob IDs (over prefix and ciphertext).
- There is no thing hash and no state hash.

## 8. References
- A **reference** (ref) is a strong, a weak or a ticket inside a value. A **strong** makes its target part of the closure of the thing holding it (spec/sync-set.md §2); a **weak** only points; a **ticket** is a weak that also carries what syncing its target needs (Tickets). A strong and a weak to one tid are different values.
- A reference grants nothing: anyone who may write a value may write a reference to any tid in it, and removing one revokes nothing (spec/permissions.md §1).
- Types bind the local writer only (spec/versioning.md §5): a reference counts by the kind written, whatever type its position has or whether any schema types it.
- **What counts**: a thing's references are those in the current value of each of its aspects as an untyped read returns it (`roles.0`: its roster, §9), at any depth (map keys, set elements and unknown tags' content included; a ticket's content holds tids, no references) and any value size (§6), an ephemeral aspect's while the node holds its value. History counts only as Held history says, a value-less write never. A signal has no current value: a reference in a fire adds nothing to a closure.
- **Held history**: on a thing whose current setting has `history_holds_targets` (spec/commits.md §5 The setting), a strong in a held valid body (spec/commits.md §5 Bodies and deaths, live or replaced, a snapshot's included) of a durable aspect of it that is no signal and has no fixed retention (spec/commits.md §5 Fixed retention) makes its target part of the closure as a strong in a current value does, while the node holds that body: until it drops (as covered, by expiry, by purge request, as invalid) or the thing is released. A body in history is dropped by none of these but expiry, purge and invalidity (spec/commits.md §5 Keep bounds), so a strong in the history a setting promises holds its target at least while the version is in history; past it, until a cover drops the body. Weaks and tickets in history count for nothing; nor are such strongs known references.
- **Known references**: a node knows every reference in the current values (What counts) and in the held fires of the things it holds and may read, each with its kind, the thing and AK holding it. Backlinks of a thing list every known reference to it, from any aspect. A ticket for a thing is found among them by the thing's tid (spec/sync-set.md §2).

### Tickets
- A ticket's content is `[target, sync_id, role, epoch, box, holder, profile]`:
  - `target`: the target's tid; `sync_id`: its sync ID (spec/sync-ids.md §2), 16 bytes;
  - `role`: the role of the secret as a uint, its `role` case ID (§9): read (0) or sync (3);
  - `epoch`: `[n, nonce]`, the secret's epoch (spec/crypto.md §4), `n` a uint, `nonce` 32 bytes;
  - `box`: a `box` value (§9) holding the target's secret of `role` at `epoch`, boxed to `holder` exactly as a `secrets.0` box of the target to that holder is (spec/crypto.md §4 Boxes; AD and payload: spec/wire.md §7);
  - `holder`: the tid of the thing the box is to; `profile`: the tid of the issuer's profile (spec/sync-set.md §1).
  - Tids are 15-byte byte strings. A decoder rejects any other shape (as tag content), and any other role.
- A ticket carries no address and adds nothing to a closure: it is a weak to its target.
- A node **can open** a ticket when it holds a key its box opens under (spec/crypto.md §4 Boxes). The opened secret is held as the secret of the epoch the box names, as any box's, establishes nothing (spec/crypto.md §4) and is taken only as spec/permissions.md §3 No secret taken back allows.
- A ticket is made from a secret of the target its maker holds, boxed to a holder of `role` or above on the target as the maker judges it, by one of:
  - a node that may grant `role` on the target (spec/permissions.md §2: admin on it, or an effective invite of `role` or above);
  - a node changing the target's keys, for each holder the change boxes (spec/sync-inbox.md §5 Key changes);
  - a node for its own account: it grants nothing, the account already holds the role.
- Anyone may copy one. Nothing signs it: its `sync_id` is its issuer's word (spec/sync-inbox.md §5 Ticket sync IDs) and `profile` a dial hint, never proof of who issued it.

### `holds.0`, `tickets.0` and tags
- `holds.0` (`set<ref>`: strongs and weaks, never a ticket) is a plain container: its references count as any (What counts). The node root and the account root hold their strongs there (spec/sync-set.md §1).
- `tickets.0` (`set<ticket>`) is a plain container of tickets, as `holds.0` is of strongs and weaks: its tickets work as any held ticket (spec/sync-set.md §2). The account root holds its tickets there (spec/sync-set.md §1 The account's tickets).
- A **tag** is a thing with `holds.0` and `tag.0`: what it tags is what its `holds.0` references. `tag.0` marks it as one users see.

## 9. Core schema
The core aspects form the core schema, evolving under spec/versioning.md. `schema/core.osis` (normative, in the DSL of notes/data-model.md) gives their exact types, flags and default retentions; `creation`, `signing_key`, `signature`, `kem_key`, `sealed` are spec/wire.md §3. Rules beyond the types:

- `roles.0` reads as the role timeline's roster (spec/permissions.md §5). `floor`: spec/permissions.md §2. `until` 0: a removal saying retain; `retain`: what a timed grant's `until` passing says (spec/permissions.md §2).
- `addenda.0` is read per delta, never as state.
- **`vouches.0`**: `map<blob, frontier>`, a removal's 32-byte commit ID to the 32-byte commit IDs its writer vouches for (spec/permissions.md §5.1 Vouches); each entry only put (`put_new`): a delta writing it otherwise is bad input (spec/commits.md §4); read per delta, never as state; a role part (spec/crypto.md §4 Roles secrets), never compaction-snapshotted (spec/commits.md §2).
- `keys.0`: spec/crypto.md §3, spec/sync-ids.md §2; `signing` is set only on an account's (the current epoch's signing key; `key` beside it is that epoch's KEM key). `secrets.0`: spec/crypto.md §4. `sync.0`: spec/sync-ids.md §4. `reach.0`: spec/sync-transport.md §3 (a node's dialable key, its global addresses and relays). Box payloads, history box layout and AD tuples: spec/wire.md §7.
- **References in core aspects**: every thing a core aspect's value names (schema/core.osis) is named by a weak: a creation record's `admin` and `link`, `roles.0`'s holders, box keys' holders, `left_out`'s holders, `reach.0`'s account, `keys.0`'s inbox, `caps^.0`'s things, `clients^.0`'s client actors; but `holds.0` holds refs and `tickets.0` tickets.
- `node.0`, `reach.0` are written on node things; `caps^.0`, `clients^.0` on the node root (spec/sync-set.md §1); `dial^.0` on an account's profile; `ticket@~0`, `removal@~0`, `stranded@~0` on an inbox and on each thing with a sync ID that is not an account (spec/sync-inbox.md §1). `node.0` and `reach.0` go under the account root D's sync ID only (spec/permissions.md §4). A node's last sync is its own record; stranded reports go over connections and as `stranded@~0` fires, suspect lists over connections only (spec/permissions.md §4).
- **`account.0`** on an account's D: `set<blob>`, the 32-byte signing public keys (spec/crypto.md §3) of the epochs whose seeds the account's commits on D box: added by the commit creating the account and D (its first epoch), by each rotation (the epoch it mints) and by each seed re-seal (the epoch whose seed it boxes, spec/crypto.md §9), so each travels under D's sync IDs. It marks D as the account's.
- **`listing.0`**: `map<blob, set<blob>>`, a rotation's 32-byte commit ID to the 32-byte commit IDs a listing names (spec/permissions.md §5.5); entries only put, never reset. Read per delta, never as state.
- `retention^.0`: what the thing keeps of replaced content per AK, the expiry a writer gives its writes there, `final` (a writer replaces no fire there) (spec/commits.md §5 The setting), and its removal default (`retain`, spec/permissions.md §2, §3); admin-only, ordinary retention.
- `purge.0`: the delta a purge request naming no aspect to reset carries (spec/commits.md §5).
- `holds.0`, `tickets.0`, `tag.0`: §8.
- **`caps^.0`**: the limits (`policy`, per-thing `things`, applied to each sync ID the thing owns) on what peers may make the node store of the sync IDs it keeps unread (spec/sync-ids.md §5); local policy, absent: the defaults.
- **`ticket@~0`**, **`removal@~0`** and **`stranded@~0`** (spec/sync-inbox.md §1), the only core signals, all external (`@`): a `ticket@~0` fire is `struct { thing 0: ticket, profile 1: option<ticket>, grant 2: option<struct { commit 0: blob, chain 1: list<blob>, records 2: list<blob> }> }` (spec/sync-inbox.md §5; `grant` as a removal notice's fields); a `removal@~0` fire is `struct { commit 0: blob, chain 1: list<blob>, records 2: list<blob> }`, a removal notice (spec/sync-inbox.md §5); a `stranded@~0` fire is `struct { sync_id 0: blob, holder 1: weak, keys 2: list<blob>, records 3: list<blob> }`, a stranded notice (spec/permissions.md §4 Stranded): the sync ID, the holder, and its holder keys (`keys` the `CommitBlobPlaintext` values, `records` the `creation` values, spec/wire.md §9 Holder keys).
- **`dial^.0`** on an account's profile: `map<blob, list<text>>`, a node's dialable key to its URLs (spec/sync-set.md §1; spec/sync-opens.md §1); written by the account, each node keeping its own entry; read by contacts.
- **`clients^.0`**: clients acting as a thing of their own, by client actor (spec/sync-transport.md §6).
  - `secret_hash`: BLAKE3 of the client's 32-byte bearer secret. `until`: when its sessions end.
  - The client actor is an independent thing whose mint admin is the node's account, and what the client may do is its roles.
- **Role-class aspects**: `roles.0`, `secrets.0`, `keys.0`, `sync.0`, `account.0`, `listing.0`, `vouches.0`. Their rules: spec/commits.md §2, spec/permissions.md. `addenda.0` is content with the retention of a role-class aspect (spec/commits.md §5), never compacted. Role-class aspects, `addenda.0`, `retention^.0` and `purge.0` have the fixed retention of spec/commits.md §5.
- `creation` holds exactly one of fields 0 and 1 (spec/wire.md §3): `created.0` is typed by that rule, not by the missing-field rule of spec/versioning.md §5.

## 10. Schemas
- A schema has a **revision** (integer, bumped on every publish), for people and tools only: no schema ID or revision travels on the wire or is attached to aspects (spec/versioning.md §3).
- A parsed schema is itself an osis value, of type `schema` in `schema/meta.osis` (normative); its canonical form is the canonical encoding of that value. The core never distributes schemas.
