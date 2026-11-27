# Stub rewrite: owed and open
> Summary: What the stub rewrite (design: notes/stubs.md; rules: the spec) still owes, and its open questions for Tess, each with options and the working answer as built.

## Status
On main: spec, engine, osis-sync and the models. Tess approved the shape and took the working answers below; she may revise any. A decision is recorded by changing the spec and deleting its question here.

## Decided (Tess), to build
- **Stores may learn a padded holder count** (opening by entries, built: spec/sync-ids.md §3): the spec/requirements.md privacy line to change (Tess: not worried); wording owed for her sign-off, with "the grant's notice" → the grant signal.
- **Settled without her**: pairing hands over no trust records (each node sides by its own trust set).
- **Later (Tess)**: a pass over dependent and independent things, a weak to a dependent thing its independent's unit does not hold among them.

## Owed
- **Failing since entries landed**: issues/entries-open-failures.md (6 osis-sync tests). Entries do not page: issues/entry-blocks-unpaged.md.
- **Tests**: a removed stub holder served its removal by its older proof (`stubs::a_two_hop_chain_*` asserts only that nothing written since is read); a new node syncing a unit catching up from the stub it carries.
- **Ignored, cause not sorted**: `public::removing_the_public_ends_*` and the rest `tools/ignores.py "stub rewrite: "` lists (engine 8, osis-sync 14).
- **Full-size differential classes**: issues/differential-full-size-classes.md.
- An external signal on a dependent thing: issues/behaviour-depends-on-own-keys.md. Each stub one more followed sync ID: issues/many-sync-ids-cost.md.
