# Set elements are stored as nested fragments, not as one register
> Summary: The spec stores each set element's value as a single register, but the code (and the CRDT model) stores a struct- or map-typed element as a nested fragment. Bytes on the wire differ from the spec for sets of structured values, so another implementation would not interoperate; this must be settled before a release.
> Tags: crdt, data-model

Repro: no failing test. `osis_crdt::ops::create` builds a set element with the element view's encoding (`(Encoding::Set, Value::Set(items))` arm: `create(w, &ev, it)`); `models/crdt` `ops.rs` does the same. spec/crdt.md §3.3 ("Set elements have no key; their value is a `Register` fragment"), §4.7 and §5.1/§5.5 say a register.

Consequences:
- `/tenures` (`set<tenure>`) elements are struct fragments; a linked tenure frontier (spec/permissions.md §6) is a link at a struct position, so `create` has a narrow `(Encoding::Struct, Value::Link)` → register arm and spec/crdt.md §3.1 a matching sentence. Both go once elements are registers.
- A whole large set element chunked to a link (spec/data-model.md §6) cannot be written at a struct-typed element position today.

Fix: register-encode set element values in osis-crdt and models/crdt (byte vectors and tests regenerated), then drop the struct-link arm and the §3.1 sentence.
