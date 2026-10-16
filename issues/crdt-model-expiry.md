# Reference model lacks expiry and snapshot frontiers
> Summary: crdt-model does not implement value-less writes / expiry (spec/crdt.md §4.7) or snapshot frontiers (§8), so those rules are unchecked.
> Tags: crdt, tests

Added to the spec 2026-10-16 without model support. Needed:
- `Option<Value>` (or a value-less marker) on register writes, enum case writes, map keys, seq content; join prefers the valued copy; presence ignores value-less writes; reads treat value-less creations as not live.
- Wire forms `[0, R, Stamp]`, `Case [[Stamp]]`, keyless `Entry`, value-less creation runs (`Content []`), snapshot `Frontiers`.
- Proptests: convergence with expiry applied at random points per node and stripping on later arrival; strip commutes with join; round trip of the new forms.
