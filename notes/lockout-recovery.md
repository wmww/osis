# Lockout recovery
> Summary: A writer that rotates keys sealed only to itself locks everyone else out; removing that holder is the recovery. The removal's rotation lists the current epochs the remover cannot open (all made by nodes holding no write once it applies), so they are superseded, not invalid; a removal blocked by a kept writer's epoch goes alone. No lockout concept in the API or UI (Tess). Model: core/test/tla/rotation/Lockout.tla.

## The case
Writer W rotates read and write of A boxing only itself (or garbage to the others). Its epoch e_W is valid and established everywhere (a node lacking a secret establishes an epoch from its commit alone), supersedes e_n, and no other node holds a current secret. Such a node makes no rotation (spec/crypto.md §4, Boxes), so before this rule it could not remove W either.

## The rule (spec/permissions.md §3 Lockout recovery, spec/crypto.md §4 Boxes)
An admin removes W (or demotes it below write) with `set_role`, like any holder: full frontier, every received rotation of W listed and valid. The required rotation is the ordinary one, made although the remover holds no current secret of the role, when every current epoch it lacks was made by nodes holding no write on A once this removal applies (each held valid rotation commit of it signed by such a node; an epoch known only from a snapshot has no maker, so blocks):
- n = greatest n of the current epochs (e_W included);
- the keyset lists every current epoch, e_W included;
- the history box carries the established secrets it holds (e_n and earlier), not e_W's;
- the commit wraps under the greatest-n superseded read epoch whose secret it holds (spec/crypto.md §5): the history box lists e_n, so e_n is superseded and the ordinary rule names it. `osis_keys::produce::rotate` and `RoleEpochs::wrapped_under` both pick from the superseded held epochs.

"Holds no write once this removal applies" is the signer's role on A over the current edges with the removal's edge changes patched in (`rotation::lacked_made_by`, an `osis_perm::graph::View` with the overlay set). One rule covers: W itself; W's own devices and a team's writers (their write came through W); writers removed earlier (an earlier vandal, an honest writer that left). It is judged now, not at the commit. Such a node's honest epoch the remover lacks is superseded with the rest: no secret leaks (the recovery carries only what the remover holds), and its holders keep reading it, as in "A rotation by W that missed the admin" below. W keeping write another way (directly beside a removed team actor) blocks: that removal goes alone and removing W recovers.

**Blocked: the removal goes alone.** A lacked current epoch whose maker keeps write (an honest writer whose rotation missed this node, or a second vandal) blocks the rotation; the removal then goes alone, its departure uncovered (spec/permissions.md §3, as while Seal waits): nothing superseded, no node knowing it encrypts under A until a node that may rotate does. An honest kept writer holds a current secret, so its due rotation covers the departure (and boxes the admin, or re-seals it). Two vandals V1, V2 rotating concurrently from one epoch: removing V1 goes alone (V2's epoch blocks), removing V2 then recovers both (V1 holds no write any more); either order. What a locked node writes meanwhile commits locally and seals nothing under A (it holds no current secret).

**Limit: a vandal that left.** W rotates to itself, then removes itself: its leaving carries no rotation, and a node lacking every current secret makes no due rotation, so the admin recovers only through a removal or demotion of some other holder (any one: W holds no write; `vandal_that_left_recovered_by_any_removal_spec_perm_3`). issues/lockout-vandal-left.md.

Receivers apply the ordinary Supersedes rule: e_W is superseded, the recovery epoch alone is current, every holder it boxed holds it. Code: `rotation::lacked_made_by` decides rotate-or-alone in `flows::edges::demote_in`.

**Things below.** W may also have locked things A's roles open (it rotated T boxing A at its own e_W keyset of A). After a removal commit that rotated, `rotation::recover_reached` rotates each such thing (nearest first) whose role the remover may rotate, holds no current secret of, and lacks only epochs made by nodes holding no write on it. It must happen then: only a removal may rotate lacking current secrets, so no later rotation of T could be made.

**Why a kept writer's epoch blocks.** It is often an honest epoch the remover merely missed (a stranded admin); superseding it unheld would drop it from the history boxes with no lockout to cure. Going alone costs only delay: the kept writer rotates.

**Seal waits.** An ordinary or blocked removal goes alone while Seal waits; a recovery fails `SEAL_WAITS` instead (nothing written), since only a removal's own rotation may list epochs the remover lacks and this removal alone would leave A locked until another removal. Limit: W can name, in its boxes to a holder actor M at e_W, a valid keyset of M on a fork M's newest does not list; Seal's anchors then fork and the recovery waits until M merges (Seal reads anchors from boxes at current epochs, e_W's included).

**Rejected: a fork from the admin's own epochs.** It leaves e_W current beside it; lowest-nonce ties are the rogue's to grind; the covers rule then forces a rotation listing e_W anyway. Model `L_fork` fails `Unlocked`. **Rejected: frontier omission** (leaving W's rotations out of the removal's frontier so they turn invalid): a recovery resting on a protocol side effect (Tess); an admin wanting a write gone reverts it.

### What the rogue's writes become
- Its rotation commit: valid (listed). Its epoch: established, superseded. Its box removals at e_n stand (harmless; e_n is in the new history box).
- Its content under e_W: no other node can unwrap it, so none was received, so the frontier does not list it, so it is invalid by the ordinary rule.
- Its content before rotating, and anything the admin received: valid. An admin wanting it gone reverts it.
- Rotations racing the removal: unreceived, unlisted, invalid; ones ordered after it invalid outright.
- W keeping write another way (another path to A) is not stopped: once boxed again it can rotate again. Remove that path too.

### A rotation by W that missed the admin
It stays valid and its holders keep reading; the recovery boxes them its epoch too, and their next rotation's history box carries the missed epoch to everyone after. Limit: until a holder of it next rotates, later joiners cannot read content under it. `L_list_honest` and `Repairable` check this.

## Disputes (notes/disputes-plan.md)
A writer lockout is no dispute: every view agrees W's rotation is valid, the removal is valid and the recovery epoch supersedes W's.

A hostile admin is a dispute, and the same recovery is what the recovering side does: its removal lists what it received and its rotation lists the admin's epochs it cannot open (admin role included). On its side those are superseded; on the other side its removal is void (step 6's "each side rotates its own epochs"). Open for step 6: an admin that rotated to itself can also register a host step from its epochs; a child step needs the head's delete key, derived from the hostile epoch. Fix planned: a registrar also branches, from the newest step on the path whose delete key it holds, when the head's step registers epochs its own current epochs supersede and it lacks the head's delete key (notes/disputes-plan.md, Register gains a branch form). A writer cannot register steps.

## Model
`core/test/tla/rotation/Lockout.tla` (README section): `Mode = "list"` is the rule (rotate when every lacked epoch's maker holds no write once the removal applies, else go alone). An honest rotation names the removals its maker held and is established only with them held (names met): without that, a node holding the second removal's epoch but not the first would box the first rogue its history. `L_list`, `L_list_honest`, `L_list_missed` (h's rotations leave a out; the removal goes alone and h's due rotation follows) and `L_two` (two rogues, any removal order) pass; `L_probe_refused` confirms a blocked removal is reached; `L_fork` fails `Unlocked`, `L_none` (no recovery) and `L_two_own` (only the removed rogue's epochs may be lacked) fail `RemoveOK`. Not modelled: several roles, holder actors, things below, compaction, hosts.
