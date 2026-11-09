# History entry names and lists outlive the entry
> Summary: `EpochInfo::names` and `supersedes` accumulate from every history entry ever opened, with no record of which `secrets.0` body carried it. An entry that leaves the state (its delta judged invalid and un-merged, or overwritten) keeps establishing its epoch (names) and superseding what it listed at nodes that opened it while live, not at nodes that never did. Establishment then depends on arrival order. Not reached by a test.
> Priority: normal
> Tags: keys, engine, security

## Shape
- Rule (spec/crypto.md §4 Established): "some *live* entry of e's history box ... has its names met"; Supersedes: "the epochs e's history box lists". `osis_keys::open_histories` adds names and the listed epochs; `RoleEpochs::invalidate` removes only `rotations` and `snapshots` (both keyed by commit), so nothing removes names or listed epochs.
- Honest entries of one rotation carry the same names (every history box of a rotation carries them, re-seals copy them), so only a holder writing an entry with other names (bound to nothing, which the spec allows while it is live) reaches it: holder X writes such an entry while its role is being removed unaware; node P applies it before the removal and keeps e established by it; node Q gets the removal first and never applies it. No new leak (X holds e's secret and could hand it out anyway); the property broken is "establishment is a function of held commits".
- Same class as the two inputs made commit-keyed for this reason (`rotations`, `snapshots`) and derived establishment computed on read (`Core::own_epochs`).

## Options
- Record each opened entry's names and list by the body that carried it (as `rotations` and `snapshots`), dropped with it by `invalidate`; an overwritten entry needs its record replaced too.
- Or compute both from the current `secrets.0` state on read (open the live entries each time): plain, costs an AEAD open per live entry per read; cache per state change.
