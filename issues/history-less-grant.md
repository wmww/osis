# Grants without history: what is left
> Summary: Grants without history (osis `GrantOpts::reads`; notes/history-less-grant.md) are built and read across sync. Left: from now through holders (Tess decided; design below, model first), certificate copies before the cut, the per-thing default, the expiring snapshots' cost, and the sync side.
> Priority: normal
> Tags: security, spec, perm, keys, crypto, engine, sync

## From now through holders (decided, Tess: transitively, where practical)
A newcomer N granted on G without history must read every thing G holds a role on (a realm's channels), transitively, as it reads G: the current state, no past. Today it reads their whole history: G's cut is a rotation of G, each thing T holding a box to G finds it stale (spec/crypto.md §4 Holder actors) and rotates, sealing G at the cut's keyset k, and that rotation's history box carries T's earlier secrets to N. Design (new rules across holders, so model first):
1. **A cut keyset**: G's keyset at a cut records that it is one (spec/wire.md §7, one flag), judged only on a keyset whose rotation commit (carried to T's sync IDs) is a grant without history by an admin of G, its `roles.0` delta carried with it (else a history-less writer of G clears the flag).
2. **A holder's floor on T**: a keyset of G that is or descends from a cut keyset is boxed at an epoch of T only where that epoch's rotation boxes it itself and writes a floor of at least its own n (a cut on T); never by a grant, re-seal or tip add at an older epoch.
3. **The rotation** staleness forces is then a cut on T whenever it seals such a keyset; G's earlier keysets keep their boxes at T's earlier epochs, so G's members with history still read T's past.
4. **Transitive**: T's cut is a cut keyset of T, so each thing T holds a role on cuts likewise.
- Cost to settle in the model: each such rotation is a cut (a snapshot per aspect of T per history-less join on G), and every cut leaves a dropped epoch on T, so a later grant with history writes one box per cut.
- Before building: extend Cut.tla with one holder (keysets, staleness rotation, a forged flag) and check NoPast for N on T, PriorKeep for G's members with history.

## Engine
- **Certificate copies before the cut**: a newcomer judges a pre-cut write by the evidence S carries, but a certificate copy of a role commit on a thing outside S's unit is wrapped under the read epoch it was logged at (`Engine::wrap_secret`), so the newcomer opens none from before its cut (hidden in tests where the author is a contact). Fix: certificate copies under the roles secret too (check that a copy carries nothing a newcomer must not read), or log again what a newcomer lacks. The same for the `roles.0` copies a keyset's carried demotions bring.
- **The default**: a per-thing default for whether grants hand history (Tess: per grant, with a default; an aspect set as the history setting is). The API has the per-grant option only.
- **Expiring snapshots' cost**: a cut writes one expiring snapshot per distinct expiry of a live value (`snapshot::write_expiring`), and `snapshot::expiring_copies` decodes every held snapshot of the aspect whole on each snapshot write and each undo of a part. Options: bucket expiries (ending values early at the holder, never late), or judge only the dots an undo touches.

## Sync
- **Role commits from before a cut**: a newcomer opens their `roles.0` sections and their blobs' wraps under the roles secrets its cut's history entry carries (`Engine::read_secrets`); it must fetch them wherever in the log they lie and not stop at a body it cannot open. Untested beyond the author being a contact.
- **Pre-cut bodies logged again**: `Engine::wrap_secret` gives `None` for a blob carrying a part that may not go under the newest epoch, so a pre-cut body that must be logged again (past a delete) is not; wrapping it under the epoch it was opened under would serve holders with history.
- **First-sync fetch**: a history-less holder fetches pre-cut content bodies it cannot open, for nothing; it should skip bodies below its floor that are not role commits (issues/partial-history-fetch.md). Whether it can open a blob is known only by trying its wrap.
