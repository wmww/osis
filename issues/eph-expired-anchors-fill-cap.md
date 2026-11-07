# Expired ephemeral writes leave anchors that fill a holder's cap
> Summary: An expired ephemeral list element or fresh map entry stays in the aspect's state as a value-less anchor (as durable tombstones do), charged about 1.15 KB each at holders; they are never collected while any holder keeps the aspect, so an ephemeral event list or per-message map hits the 16 MiB node cap after about 14,000 expired elements over its lifetime, and the label's ephemeral data is then refused.
> Priority: normal
> Tags: ephemeral, crdt, node

Follows from the principle (notes/ephemeral.md: durable semantics held in memory): expiry keeps the writes value-less, and a snapshot carries them (spec/crdt.md §4.7, §8). Durable state keeps the same tombstones at 3-4 B each, run-compressed (notes/growth.md); in memory a decoded anchor is charged `Engine::memory_charge` (decoded heap twice plus part overhead): measured about 1.15 KB per list element (`scale::eph_leftover_memory`).

Bounded per key: a value kept alive at one key (a cursor or online mark keyed by node) leaves one anchor per key ever used. Unbounded per write: list elements (buffered events, notes/ephemeral.md Expiry), measured; map entries at fresh keys (a message per key) keep their key-erased entry records, unmeasured. A restart frees nothing while another holder serves the snapshot back.

Options: a compact in-memory form for runs of value-less anchors (charged near their encoded size); or a stated limit in notes/ephemeral.md Bounds (lifetime elements per label = cap / 1.15 KB). Either keeps the durable rule.
