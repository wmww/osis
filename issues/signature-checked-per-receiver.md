# A stamp verified more than once per receiver
> Summary: A commit's signature is checked once per node (notes/engine.md, Signature verdicts), but osis-sync verifies an entry's stamp where the store logs it (`Store::log`, core/sync/src/store/mod.rs), again in `read` (core/sync/src/read/live.rs) and at every head move per stamped carrier (`charge_unvouched`): the same (key, blob, wrap, stamp) checked again where a verdict kept with the entry would answer.
> Priority: normal
> Tags: sync, performance

An entry's stamp is a function of its bytes and the write key it verified under, so its verdict belongs with the entry where it enters (as `Signed` is kept with a commit), keyed by exactly what verified (the key included: a head key moved later is checked anew). A re-check that guards a different input says so. Count first with `Domain::verify_cost` per write at n and 10n writes.
