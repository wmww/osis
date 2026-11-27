# Stub rewrite: owed and open
> Summary: What the stub rewrite (design: notes/stubs.md; rules: the spec) still owes, and its open questions for Tess, each with options and the working answer as built.

## Status
On main: spec, engine, osis-sync and the models. Tess approved the shape and took the working answers below; she may revise any. A decision is recorded by changing the spec and deleting its question here.

## Decided (Tess), to build
- **Stores may learn a padded holder count** (opening by entries, built: spec/sync-ids.md §3): the spec/requirements.md privacy line to change (Tess: not worried); wording owed for her sign-off, with "the grant's notice" → the grant signal.
- **Open (Tess)**: a node holding a thing only at sync through a chain (it syncs H, H holds sync on X) keeps X unread in the model and holds X as a stub in the engine (differential seeds 81, 99; the untold read chain alike, seed 28: issues/differential-full-size-classes.md). Two gaps:
  - **Sealing** (decided, Sheave): an entry is sealed to the keyset of the holder its box in that commit is to, so a sync holder's entry goes to its sync keyset's KEM key and claimants try sync keysets too. Not built: no test can fail without it while the second gap stands (nothing names a sync-only holder to a node that holds only its sync secrets but a node-thing grant, which the harness cannot make).
  - **Finding the holder**: nothing names H to the node as a holder it reaches X through. X's roster is X's role entries, which a node holding X's sync secret alone (or none) cannot open; a grant to a plain thing tells nobody (H names no inbox); a unit's chain stubs follow read hops only, and a sync-only cut names the unit's thing alone. held-model abstracts this away ("every node follows the stubs it holds, so the grants it knows are the world's current ones"), so its oracle gives nodes grants they cannot learn (the same gap made `public::removing_the_public_ends_*` expect a removal its reader's one source cannot carry).
  - Options: (a) a sync-only cut names the holders on the sync chain from the unit's thing to X (its logger reads X's roster) and a node holding it claims as them with their sync keysets (needs the sealing rule); a chain through sync hops is then entered as one through read hops is; (b) the model counts a holder only where the node can learn it (X's roster opened, a cut, a signal or an own thing naming it), so such a node holds X as a stub and seeds 81/99 are oracle bugs. Working answer: none; (a) completes what the sealing decision started, (b) is smaller.
- **Entries do not page** (issues/entry-blocks-unpaged.md): a commit boxing more than about 4000 holders cannot be made; options there.
- **Settled without her**: pairing hands over no trust records (each node sides by its own trust set).
- **Later (Tess)**: a pass over dependent and independent things, a weak to a dependent thing its independent's unit does not hold among them.

## Owed
- Entries do not page: issues/entry-blocks-unpaged.md.
- **Tests**: a removed stub holder served its removal by its older proof (`stubs::a_two_hop_chain_*` asserts only that nothing written since is read); a new node syncing a unit catching up from the stub it carries.
- **Hand-delivered grants**: engine tests handing a node a grant's commits directly (`LocalPeer::share` and its users) enter the thing from the node root with no grant signal; whether that is a held role entry (fine) or self-supporting entry (spec/sync-set.md §2 First entry: Entry is founded) is unsettled. Judge before relying on it in new tests.
- Where a record edge's removal travels once it takes a thing out of its mint admin's unit: issues/record-edge-removal-carriage.md (Tess).
- **Full-size differential classes**: issues/differential-full-size-classes.md.
- An external signal on a dependent thing: issues/behaviour-depends-on-own-keys.md. Each stub one more followed sync ID: issues/many-sync-ids-cost.md.
