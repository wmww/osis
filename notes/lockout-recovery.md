# Lockout recovery
> Summary: A writer that rotates keys sealed only to itself locks everyone else out; removing that holder is the recovery. The removal's rotation lists the current epochs the remover cannot open (all made by the removed holder), so they are superseded, not invalid. No lockout concept in the API or UI (Tess). Model: core/test/tla/rotation/Lockout.tla.

## The case
Writer W rotates read and write of A boxing only itself (or garbage to the others). Its epoch e_W is valid and established everywhere (a node lacking a secret establishes an epoch from its commit alone), supersedes e_n, and no other node holds a current secret. Such a node makes no rotation (spec/crypto.md §4, Boxes), so before this rule it could not remove W either.

## The rule (spec/permissions.md §3 Lockout recovery, spec/crypto.md §4 Boxes)
An admin removes W (or demotes it below write) with `set_role`, like any holder: full frontier, every received rotation of W listed and valid. The required rotation is the ordinary one, made although the remover holds no current secret of the role, when every current epoch it lacks was made by a holder it removes (each held valid rotation commit of it signed by that holder or by a node holding write or above on it; an epoch known only from a snapshot has no maker, so refuses):
- n = greatest n of the current epochs (e_W included);
- the keyset lists every current epoch, e_W included;
- the history box carries the established secrets it holds (e_n and earlier), not e_W's;
- the commit wraps under the greatest-n superseded read epoch whose secret it holds (spec/crypto.md §5): the history box lists e_n, so e_n is superseded and the ordinary rule names it. `osis_keys::produce::rotate` and `RoleEpochs::wrapped_under` both pick from the superseded held epochs.

A commit's signer is a node, so "or by a node holding write or above on it" is what counts a person's own devices (and a team's writers) as that holder; it is judged now, not at the commit. Such a node's honest epoch the remover lacks is superseded with the rest: no secret leaks (the recovery carries only what the remover holds), and its holders keep reading it, as in "A rotation by W that missed the admin" below.

**Limits.** Two colluding writers that each rotate concurrently from the same epoch lock A for good: removing either refuses on the other's epoch, and `set_role` removes one holder per commit (issues/lockout-two-writers.md). An epoch a node knows only from a `secrets.0` compaction snapshot (it joined after the compaction) has no maker there, so that node cannot recover; one still holding them can.

Receivers apply the ordinary Supersedes rule: e_W is superseded, the recovery epoch alone is current, every holder it boxed holds it. Code: `rotation::lacked_made_by` gates the refusal in `flows::edges::demote_in`.

**Things below.** W may also have locked things A's roles open (it rotated T boxing A at its own e_W keyset of A). After the removal commit, `rotation::recover_reached` rotates each such thing (nearest first) whose role the remover may rotate, holds no current secret of, and lacks only epochs made by the removed holders. It must happen then: later the removal's context is gone and no rotation of T could be made.

**When it refuses.** A current epoch the remover lacks that a kept holder made: it waits for a re-seal, as a stranded node does (`L_list_missed`). Safe without asking: the honest case that looks like a lockout is W rotating boxing others but missing this node; removing W there costs only delay, never data (below).

**Seal waits.** An ordinary removal goes alone while Seal waits; a recovery fails `SEAL_WAITS` instead (nothing written), since only its own rotation may list epochs the remover lacks and a removal alone would leave A locked for good. Limit: W can name, in its boxes to a holder actor M at e_W, a valid keyset of M on a fork M's newest does not list; Seal's anchors then fork and the recovery waits until M merges (Seal reads anchors from boxes at current epochs, e_W's included).

**Rejected: a fork from the admin's own epochs.** It leaves e_W current beside it; lowest-nonce ties are the rogue's to grind; the covers rule then forces a rotation listing e_W anyway. Model `L_fork` fails `Unlocked`. **Rejected: frontier omission** (leaving W's rotations out of the removal's frontier so they turn invalid): a recovery resting on a protocol side effect (Tess); an admin wanting a write gone reverts it.

### What the rogue's writes become
- Its rotation commit: valid (listed). Its epoch: established, superseded. Its box removals at e_n stand (harmless; e_n is in the new history box).
- Its content under e_W: no other node can unwrap it, so none was received, so the frontier does not list it, so it is invalid by the ordinary rule.
- Its content before rotating, and anything the admin received: valid. An admin wanting it gone reverts it.
- Rotations racing the removal: unreceived, unlisted, invalid; ones ordered after it invalid outright.
- W keeping write another way (another path to A) is not stopped: once boxed again it can rotate again. Remove that path too.

### A rotation by W that missed the admin
It stays valid and its holders keep reading; the recovery boxes them its epoch too, and their next rotation's history box carries the missed epoch to everyone after. Limit: until a holder of it next rotates, later joiners cannot read content under it. `L_list_honest` and `Repairable` check this.

## Disputes (notes/owner-removal-plan.md)
A writer lockout is no dispute: every view agrees W's rotation is valid, the removal is valid and the recovery epoch supersedes W's.

A hostile admin is a dispute, and the same recovery is what the recovering side does: its removal lists what it received and its rotation lists the admin's epochs it cannot open (admin role included). On its side those are superseded; on the other side its removal is void (step 6's "each side rotates its own epochs"). Open for step 6: an admin that rotated to itself can also register a host step from its epochs; a child step needs the head's delete key, derived from the hostile epoch. Fix planned: a registrar also branches, from the newest step on the path whose delete key it holds, when the head's step registers epochs its own current epochs supersede and it lacks the head's delete key (notes/owner-removal-plan.md, Register gains a branch form). A writer cannot register steps.

## Model
`core/test/tla/rotation/Lockout.tla` (README section): `Mode = "list"` is the rule (list every current epoch; refuse while lacking one W did not make, a re-seal by an honest holder then unblocks). `L_list`, `L_list_honest`, `L_list_missed` (h's rotations leave a out) pass `NoLeak`, `Unlocked`, `Alike`, `Repairable`, `RemoveOK`; `L_probe_refused` confirms the refusal is reached; `L_fork` fails `Unlocked`, `L_none` (no recovery) fails `RemoveOK`. Not modelled: several roles, holder actors, things below, compaction, hosts.
