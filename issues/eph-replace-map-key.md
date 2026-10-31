# Ephemeral `Replace` at a map key never reads at holders
> Summary: An ephemeral write `Op::Replace(v)` at a map key reads at its author, and a holder holds its commit, but the holder reads the aspect as absent; `Put` and `Set` there arrive. Repro: osis-node `ephemeral::repro_eph_replace_at_map_key_not_read`.
> Tags: engine, crdt, ephemeral

- Found building `osis::KeepAlive` (presence-expiry), which therefore refreshes with `Put` (a fresh entry at a map key, a register write elsewhere) rather than `Replace`.
- The sim's random cursor writes, when they were `Replace` at a key, also logged at a receiver `sync: crdt: malformed delta: nested register with a reset` (sim `ephemeral_capped` seed 2400045 at that commit): the own-state snapshot of a `Replace` at a map key likely encodes a reset on the nested register, which receivers refuse as malformed.
- Shape: window `w` (ephemeral, labeled), untyped ephemeral `map` aspect, one write `Replace("v")` at key `"k"`, no expiry. The holder's lane shows the entry and the commit held; its read is `None`. Not checked yet: whether a durable `Replace` at a map key or an ephemeral `Replace` at the root behaves, and whether the own-snapshot encoding (`own_unexpiring`, snapshot form, spec/commits.md §2) or the receiver's join drops the creation behind the reset.
