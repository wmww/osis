# Lockout recovery without omission
> Summary: Replace repudiation (`--repudiate`, the frontier's omission on purpose) with an ordinary removal whose required rotation also supersedes current epochs the remover cannot open: n above them, keyset listing them. Nothing is judged invalid; the existing supersede rule does the work. TLC: core/test/tla/rotation/Lockout.tla. Recommended; build plan issues/lockout-recovery-without-omission.md.

## The case
A writer W rotates read and write of A boxing only itself (or garbage to the others). Its epoch e_W is valid and established everywhere (a node lacking a secret establishes the epoch from its commit alone), supersedes e_n, and no other node holds a current secret: it cannot write, and by spec/crypto.md §4 makes no rotation, so no removal of W. Today's recovery (frontier study F5) removes W with a frontier that leaves out e_W's commit, so e_W turns invalid. Tess (Q6, Q7): that relies on a side effect; recover explicitly.

## Recommended: the removal's rotation lists what it cannot open
The admin removes (or demotes below write) W normally: full frontier, every received rotation of W stays valid. The rotation that removal requires is today's rotation with one restriction lifted:
- n = greatest n of the current epochs (e_W's included; already the rule: established epochs count, held or not);
- keyset lists every current epoch, e_W included (already the rule: "each current epoch at the rotator");
- history box: the established secrets it holds (e_n and earlier), as today; e_W's is not among them;
- wrap of the rotation commit: under the newest established read epoch whose secret it holds (e_n). Today's rule ("the read epoch e supersedes whose secret the rotator holds") names none here; this is the only spec rule that needs new words.

Receivers apply the existing "Supersedes" rule (spec/crypto.md §4): the new epoch lists e_W, so e_W is superseded, not invalid. Current = the admin's epoch alone; every holder it boxed holds it. No fork, no tie: a fork from the admin's own epochs (the "crypto-flow fork" of F5's question) leaves e_W current beside it, lowest-nonce ties are the rogue's to grind, and the covers rule then forces a rotation listing e_W anyway, so listing is the fork done right. `L_fork` fails `Unlocked`.

The code already does this when the remover holds one current fork and lacks another (`produce::rotate` lists every current epoch). The refusal (`edges.rs`: "lacks a current secret of the target") is only for holding none. So the change is: drop that refusal under an explicit flag, fall back for the wrap, delete repudiation.

### Why keep a flag
Holding no current secret also happens honestly: a stranded node waiting for a re-seal. Superseding then drops the unheld epoch from the history chain (and the rotation removes the boxes at it, as every rotation does), so content under it is readable only by its holders until one of them rotates (its history box carries every established secret it holds, the superseded one included). The default stays "wait for a re-seal"; the flag says "I accept losing what I cannot open". Under the flag nothing is invalidated, so the worst an honest mistake costs is that delay, not today's permanent loss.

### What the rogue's writes become
- Its rotation commit: valid (listed). Its epoch: established, superseded. Its box removals at e_n: stand (harmless; e_n is in the new history box).
- Its content under e_W: no other node can unwrap it, so none was received, so the full frontier does not list it, so it is invalid after the removal by the ordinary rule (writes the remover never received). Not an omission on purpose: the remover never had it.
- Its content before rotating, and anything the admin did receive: valid. An admin wanting it gone reverts it explicitly (Tess).
- Rotations racing the removal: unreceived, so unlisted, so invalid; ones ordered after it are invalid outright.

### Honest rotation that missed the admin (old issues/repudiation-takes-honest-rotation, closed as a stated limit)
Today: repudiation invalidates it; content others wrote under it is readable only where its secret is held, never by later joiners. Now: it stays valid; its holders keep reading; the recovery boxes them its epoch too, and their next rotation's history box carries the cut epoch to everyone after. `L_list_honest` and `Repairable` check this. The stated limit in notes/permissions.md shrinks to: until a holder of the cut epoch next rotates, later joiners cannot read content under it. A re-seal is still the better path when another holder exists; the flag's doc says so.

### What it deletes
- spec/permissions.md §3 Lockout recovery (replaced by one sentence: a removal or demotion made as recovery rotates without holding a current secret, its keyset listing the current epochs it cannot open); §5.1 "Omission on purpose" entirely (the frontier is then exactly what A received minus covered commits; no deliberate omission remains anywhere).
- spec/crypto.md §4 "...or an admin recovers" points at the new sentence; §5 wrap exception gains the fallback.
- Code: `Engine::demote_repudiating`, `lockout_rotations`, the `repudiate` omit set and its stays-valid check in `demote_in`, `remove_signed`'s `repudiate`; osis `Db::repudiate`, port `REPUDIATE`, cli `repudiate`. Added: a `recover` bool on the demotion that lifts the refusal; `rotate`'s wrap fallback.
- The "works only where the demotion audits the rotator" condition: gone. A vandal keeping write another way must still lose it (else it can rotate again once boxed), but recovery no longer refuses.
- notes/permissions.md Lockout recovery limits: first sentence shrinks as above; frontier study §7 vandal-box remark goes.

## Depth 0 (issues/keys-depth0.md)
Unchanged in substance: the lockout is about A's own epochs. Rule 2 staleness and rule 3 merge can require a rotation of A; a locked node still cannot make one without the flag, as today. One check for the depth-0 build: rule 1 reads anchors from boxes to M at A's current epochs, which include the rogue's boxes at e_W; a rogue naming a valid keyset of M on a fork M's newest does not list would leave M out of the recovery rotation until M merges (rule 3). Reading anchors only from boxes at current epochs the sealer holds removes that; cheap, worth stating then.

## Owner removal (notes/owner-removal-plan.md)
A writer lockout is not a dispute: every view agrees that W's rotation is valid, that the removal is valid and that the recovery epoch supersedes W's. No side, no trust set. So the plan's fork tolerance is not needed for it, and it needs nothing from the plan.

A hostile admin is a dispute, and the same recovery is what the recovering side does: its removal of the admin lists what it received and its rotation lists the admin's epochs it cannot open (admin role included). On its side those are superseded; on the other side its removal is void. That is step 6's "each side rotates its own epochs". One precise problem, which step 6 does not cover yet:
- **Host step after a hostile admin's rotation.** An admin that rotated to itself can also register a step from its epochs. A child step needs the head's delete key, derived from the hostile epoch the recoverer cannot open. Step 6 sends the branch form only when the registrar's view rejects the head's step; here it accepts it (the rotation stayed valid), with or without a dispute. Fix to fold into step 6: a registrar also branches, from the newest step on the path whose delete key it holds, when the head's step registers epochs its current epochs supersede and it lacks the head's delete key. Hosts already accept a branch from any path step signed by that step's delete key; nodes follow the branch registering their newest epochs. Today this case is the stated limit "a hostile admin is out of scope".

A writer cannot register steps, so the writer case never hits this.

## Model
`core/test/tla/rotation/Lockout.tla` (README section). `L_list` and `L_list_honest` pass `NoLeak`, `Unlocked`, `Alike`, `Repairable`, `RemoveOK` with any arrival order, w rotating twice, h once, concurrently; `L_fork` fails `Unlocked`, `L_none` fails `RemoveOK`. Not modelled: several roles, holder actors, compaction, hosts.
