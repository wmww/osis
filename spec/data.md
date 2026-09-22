# Types
osis has its own type system with the following types:
- `string` - UTF-8 encoded text
- `blob` - like string, but arbitrary bytes
- `bool` - boolean
- `int` - i64
- `float` - f64
- `tid` - a tid
- `enum<(N, V?)...>`
    - Enums have 0 or more cases
    - Each case has a name, and may not have a value type
- `struct<(N, T)...>`
    - Each field has a name and a type
    - All fields are required for each instance
- `list<T>` - ordered list
- `map<K, V>` and `set<T>`
    - Any type may be a map key/value or a member of a set
    - When serialized, maps and sets are deterministically ordered

## Named Types
Types can be given names and referenced by other types. This also allows recursive types, and allows creating sub-types with their own meanings. Named types can take type parameters. Some standard named types:
- `markdown` (string) - the text is formatted with markdown (markdown should not be assumed to be valid)
- `option<T>` (`enum`) - some of type T or none
- `any` - an enum with a case for each type, can represent any value

# Values
## Recursive Values
Values may be arbitrarily deeply nested, but not recursive. Alternatives to recursive values are to have a type that contains tids of things with the same aspect, or a map who's values contain other map keys.

## Serialization
osis uses CBOR for serialization.

## Large Values
Within reason, values should not be assumed or required to be small, or organized in any particular way. For example, maps with millions of keys and maps with a single multi-GB blob should be supported. Syncing should remain efficient when working with large values.

TODO: figure out details of how large values are handled

# Aspects
An osis thing is composed of aspects, each with a key and a value. The human readable form of an AK is a slash-prefixed and slash-separated string like `/somenamespace/name`.

TODO: figure out details around versioning.

## Aspect map
An aspect map connects aspect keys to their value types. It's built from loaded schemas. Each aspect in the map has a key, a type, and flags such as:
- `ro` (read-only, common for synthetic aspects)
- `synthetic` (generated on-the-fly based on other data)
- `guaranteed` (exists on all things)
- `indexed` (index text fields for text search)
- `history` (if to retain edit history of these values)

## Schema files
A schema file (using the *.osis extension) defines types and aspects for a particular usecase or application. It also contains comments describing any additional invariants that should be maintained. It can be loaded at runtime or at compile time using the `load_schema!()` macro. It uses a Rust-like DSL with a simple custom parser (no third-party parser library).

## Core aspects
These are always part of the aspect map and facilitate core functionality.
- `/tid` (tid, synthetic, guaranteed): the tid of this thing
- `/aspects`: (set of strings, synthetic, guaranteed): the AKs of aspects of this thing
- `/node` (struct): represents a sync node/device
    - (currently empty struct)
- `/group` (struct): group of things
    - `items` (set of tids): these things make up the group
    - `subgroups` (set of tids): the group also contains all items in these groups (including in subgroups of them)
- `/groups` (set of tids, synthetic, guaranteed): groups that contain this thing (including those that contain it indirectly)

# Things
Things are composed of aspects, and contain no other data.

## Tid data
Tids are randomly generated 120-bit UUIDs. The textual representation of a tid is always a 20-character base-64 URL string, using the `osis://` URI scheme when ambiguous or user-visible (eg `osis://zqf7FN-YvhtF_Dy-nqdi`), but in Rust, tids are stored as a wrapper around a private u128. Since TIDs are uniformly distributed already, hashing them is basically free.

## Tid Creation
Tids can only be created by a tid generator, or by parsing a tid string. Tid generators are seeded by the system's entropy pool and have sufficient state to avoid repeating. It is assumed no single machine will ever see the same tid twice by accident (no collision checking machinery).

## Invalid tids
Tids referenced in a value are not guaranteed to still exist/be known by the current node. They are also not guaranteed to have or still have the expected aspect(s).

## Hashing
At a given point, a thing has a single canonical hash. This implies that all values must hash deterministically, and all aspects must be known in order to hash them. Synthetic aspects are not included in hashes. Like in git, hashes are used to refer to values and construct Merkle trees.

## Groups
Things are organized into groups. Each group is itself defined by a thing, and group membership is determined by that thing's data. A single thing may be in multiple groups, and group membership may change. Groups may contain their own thing, or be cyclic.

Groups are used for sync and app-specific purposes. For example, in a spreadsheet app the toplevel spreadsheet thing might be a group that contains two axis things, each a group that contains the row and column things, themselves groups that contain the cells in those rows and columns (note that each cell therefore shows up in two groups).

# Storage
There are multiple storage implementations (in-memory, sqlite, etc). The storage API is kept clean and simple. Functionality like sync, conflict resolution, listeners, etc is kept above the storage API boundary.
