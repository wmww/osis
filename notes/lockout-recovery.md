# Lockout recovery
> Summary: A writer that rotates keys sealed only to itself locks everyone else out, and nothing recovers from that today. Design (not built, issues/lockout-recovery-without-omission.md): removing that holder is the recovery; the removal's rotation lists the current epochs the remover cannot open, so they are superseded, not invalid. No lockout concept in the API or UI (Tess). Model: core/test/tla/rotation/Lockout.tla.

## Status
No client recovers a lockout. The other holders keep what they hold and write nothing new on that thing. The spec rules for recovery by deliberate frontier omission ("repudiation") stay for receivers, marked not offered (spec/permissions.md §3 Lockout recovery, §5.1 Omission on purpose); the engine code (`Engine::demote_repudiating`, `lockout_rotations`, the omit set in `demote_in`) is used only by osis-node `flows::*_spec_perm_3` tests (issues/deprecated-terms.md). Repudiation is not offered because it rests on a side effect (Tess): an admin who wants a write gone reverts it explicitly.

## The case
Writer W rotates read and write of A boxing only itself (or garbage to the others). Its epoch e_W is valid and established everywhere (a node lacking a secret establishes an epoch from its commit alone), supersedes e_n, and no other node holds a current secret: it cannot write, and by spec/crypto.md §4 makes no rotation, so no removal of W.

## Design: the removal's rotation lists what it cannot open
The admin removes W (or demotes it below write) normally: full frontier, every received rotation of W stays valid. The rotation that removal requires is the ordinary one with one restriction lifted:
- n = greatest n of the current epochs (e_W included; established epochs count, held or not);
- the keyset lists every current epoch, e_W included ("each current epoch at the rotator");
- the history box carries the established secrets it holds (e_n and earlier), not e_W's;
- the rotation commit wraps under the newest established read epoch whose secret it holds (e_n). The ordinary rule ("the read epoch the rotation supersedes whose secret the rotator holds") names none here; this is the only spec rule that needs new words.

Receivers apply the ordinary Supersedes rule (spec/crypto.md §4): the new epoch lists e_W, so e_W is superseded. Current is the admin's epoch alone, and every holder it boxed holds it. The code already does this when the remover holds one current fork and lacks another (`produce::rotate` lists every current epoch); only the refusal for holding none (`edges.rs`: "lacks a current secret of the target") blocks it.

**When it applies, with no flag** (Tess: no lockout concept in the API or UI): a removal lists current epochs it cannot open only when every one of them was made by the holder being removed (its rotation commits, held and valid). Removing the person who locked you out then just works. Otherwise a node lacking current secrets of another's making waits for a re-seal, as a stranded node does. Safe without asking: the honest case that looks like a lockout is a rotation by W that boxed others and missed only this node, and removing W there costs only delay (its holders keep reading; later joiners read after a holder's next rotation), never data; and the remover was removing W anyway. To check while building: two concurrent current rotations, one by W and one by another holder; the rule refuses (not all W's). A Lockout.tla case for "lacks a current epoch not made by W" must keep `RemoveOK` and `NoLeak`.

**Rejected: a fork from the admin's own epochs.** It leaves e_W current beside it; lowest-nonce ties are the rogue's to grind; and the covers rule then forces a rotation listing e_W anyway. Listing is the fork done right. Model `L_fork` fails `Unlocked`.

### What the rogue's writes become
- Its rotation commit: valid (listed). Its epoch: established, superseded. Its box removals at e_n stand (harmless; e_n is in the new history box).
- Its content under e_W: no other node can unwrap it, so none was received, so the full frontier does not list it, so it is invalid by the ordinary rule. No deliberate omission: the remover never had it.
- Its content before rotating, and anything the admin received: valid. An admin wanting it gone reverts it (Tess).
- Rotations racing the removal: unreceived, unlisted, invalid; ones ordered after it are invalid outright.

### An honest rotation that missed the admin
It stays valid and its holders keep reading; the recovery boxes them its epoch too, and their next rotation's history box carries the cut epoch to everyone after. Limit: until a holder of the cut epoch next rotates, later joiners cannot read content under it. A re-seal is the better path when another holder exists. `L_list_honest` and `Repairable` check this.

### What building it deletes
spec/permissions.md §3 Lockout recovery becomes one sentence (a removal or demotion made as recovery rotates without a current secret, its keyset listing the current epochs it cannot open); §5.1 Omission on purpose goes, so the frontier is exactly what A received minus droppable commits; spec/crypto.md §4 "or an admin recovers" points at the new sentence; §5's wrap rule gains the fallback. Code: `demote_repudiating`, `lockout_rotations`, the omit set and its stays-valid check in `demote_in`, `remove_signed`'s `repudiate`. The condition "works only where the demotion audits the rotator" goes too: a vandal keeping write another way must still lose it (else it rotates again once boxed), but recovery no longer refuses.

## Depth 0
The lockout concerns A's own epochs. Staleness and merge (spec/crypto.md §4 rules 2, 3) can require a rotation of A that a locked node cannot make, as for any rotation. One check when building: Seal reads anchors from boxes to M at A's current epochs, which include the rogue's boxes at e_W; a rogue naming a valid keyset of M on a fork M's newest does not list would leave M out of the recovery rotation until M merges. Reading anchors only from boxes at current epochs the sealer holds removes that.

## Disputes (notes/owner-removal-plan.md)
A writer lockout is no dispute: every view agrees W's rotation is valid, the removal is valid and the recovery epoch supersedes W's. It needs nothing from the plan.

A hostile admin is a dispute, and the same recovery is what the recovering side does: its removal lists what it received and its rotation lists the admin's epochs it cannot open (admin role included). On its side those are superseded; on the other side its removal is void (step 6's "each side rotates its own epochs"). Open problem for step 6: an admin that rotated to itself can also register a host step from its epochs. A child step needs the head's delete key, derived from the hostile epoch the recoverer cannot open, and the branch form is sent only when the registrar's view rejects the head's step, which here it accepts. Fix: a registrar also branches, from the newest step on the path whose delete key it holds, when the head's step registers epochs its own current epochs supersede and it lacks the head's delete key. Hosts already accept a branch from any path step signed by that step's delete key. A writer cannot register steps, so the writer case never meets this.

## Model
`core/test/tla/rotation/Lockout.tla` (README section): `L_list` and `L_list_honest` pass `NoLeak`, `Unlocked`, `Alike`, `Repairable`, `RemoveOK` with any arrival order, W rotating twice and an honest holder once, concurrently; `L_fork` fails `Unlocked`, `L_none` (no recovery) fails `RemoveOK`. Not modelled: several roles, holder actors, compaction, hosts.
