# Stub rewrite: owed and open
> Summary: What the stub rewrite (design: notes/stubs.md; rules: the spec) still owes, and its open questions for Tess, each with options and the working answer as built.

## Status
On main: spec, engine, osis-sync and the models. Tess approved the shape and took the working answers below; she may revise any. A decision is recorded by changing the spec and deleting its question here.

## Decided (Tess), to build
- **Chain holders at sync** (Sheave, built): a sync-only cut names the holders on its unit's chains, chain stubs follow every hop, an entry per boxed role (notes/stubs.md). Where no reader of the unit reads the target's roster nothing names the chain, and the oracle counts only grants a node can learn. For Tess: a reader of the unit learns those holders of the target (its own chain alone); spec/requirements.md says a node granted sync "learns ... who granted it" and a node not reading data "knows none of its role holders", which a strict reading of the second breaks for its own chain's holders.
- **Settled without her**: pairing hands over no trust records (each node sides by its own trust set).
- **Later (Tess)**: a pass over dependent and independent things, a weak to a dependent thing its independent's unit does not hold among them.

## Owed
- **Tests**: a new node syncing a unit catching up from the stub it carries.
- Where a record edge's removal travels once it takes a thing out of its mint admin's unit: issues/record-edge-removal-carriage.md (Tess).
- **Full-size differential classes**: issues/differential-full-size-classes.md.
- An external signal on a dependent thing: issues/behaviour-depends-on-own-keys.md. Each stub one more followed sync ID: issues/many-sync-ids-cost.md.
