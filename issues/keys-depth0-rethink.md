# Rethink "a group never looks inside its member groups" (depth 0)
> Summary: Study done, needs Tess: keep depth 0 for keys, drop it for the ends of rights. A member actor's knowing keyset carries the demotions of its writers and admins (any depth below it), so a parent's node learns a removal exactly when the key that excludes it arrives. Closes all three removed-member leaks (issues/keys-depth0-removed-member-rotates.md) at the limit as written, and makes Possession redundant. Cost: a parent's nodes learn writer/admin demotions inside member groups.
> Priority: normal
> Tags: keys, security, tess-call

## Principle
A node grants a right through a member actor M from evidence inside M: the writer's chain certificates name its edges in M and below, at any depth (spec/permissions.md §4). So rights are already not depth 0; only keys are. The leaks live in that gap: G's admin accepts W through X1 by W's chain, and nothing makes W's removal reach it. Possession tries to stand in for the removal with a proxy (W must hold M's current secret), and a writer of M can always make the proxy say what it wants.

Proposed principle: **whatever ends a right travels with what the node needs in order to honour the end.** Requirements tie the end to M's knowing keyset ("stops reading once M's keys were changed knowing the removal and a writer of A has written since"), and that keyset must reach A's writers anyway. So the removal travels with that keyset. Two parts:
- **Keys stay depth 0.** A parent seals M by M's keysets and never learns who reads through M. A reader's removal from M reaches A only as M's new keyset. Blocked through holder actors and the Left-out mark stay as they are: they follow from "a node judges what it holds".
- **Ends of rights travel with keys.** A party that can act on A through M (write or above) is judged at A by its chain, so its demotion has to reach A. It travels as a certificate with M's knowing keyset.

This fits the other principles. It is one mechanism: an account's chain already travels to every label it acts under. Nothing waits on a party that may be gone. No device is designated: whoever places M's keyset places what it carries.

## Candidates

### A. Keep depth 0 and widen the limit (option 1 of the removed-member issue)
Rule: unchanged. Requirements limit: a party removed below M that writes A through M may read A's new content until its removal reaches A's writers.
- Leaks: all three stay, now within the limit. Nothing carries the removal to A. Placing revokes needs a node that syncs both A and the actor the removal is on. If the removed writer is the only bridge, the leak has no bound. In the rogue path, W keeps its foothold through every later rotation of A: Seal anchors on W's keyset of X1, and B never extends it.
- Bends: unchanged.
- Privacy: best. Liveness: unchanged. Complexity: unchanged. Possession stays, and it closes only the plain path (sealing M's new keyset), which an attacker never needs.

### B. Demotions travel with keysets (recommended)
Rule:
- A keyset of M lists the demotions it carries:
  - the explicit demotions on M its rotator holds that lower a role of write or above;
  - those carried by the keysets it seals M's holder actors at, where that holder holds write or above on M.
- Whoever places M's keyset under a label (Carried, Reported, holder keys) places the carried demotions with it, as certificates with their authors' chains. They stay as long as the keyset stays.
- A node holds a keyset only once it holds the demotions the keyset lists, the way an epoch is established only with its names.

Existing authority then does the rest. At A, W's role through X1 ends at the demotion. Each of W's commits on G that the demotion's frontier does not list is invalid, backdated ones too (spec/permissions.md §5.2). W's keysets of X1 are then invalid, and so is its rotation of G, so A's box naming W's keyset is stale and A rotates.
- Leaks: all three close as soon as M's knowing keyset reaches A, which is the requirement as written.
  - Made-up keyset: W's rotation is invalid, so its proofs no longer matter.
  - Backdated rotation: the frontier, not the timestamp, decides.
  - W rotating X1 itself: the demotion makes W's keyset of X1 invalid.
  - The spec's forgery and ignorant-fork limits shrink to "until M's knowing keyset reaches A's writers". Concurrent honest ignorant forks stay sealed jointly, as now.
- **Possession becomes redundant.** It covers the same cases (a removed or demoted writer through M whose end A does not know), and B closes them at the same moment. The model shows the plain path closing with Possession off (`D0_rm_np_travel`). Dropping Possession removes:
  - proofs and Shown at the role needed;
  - rotating write with read;
  - reading keysets as of a commit's key, and `Authority.tla`'s cycle;
  - the rotation that cannot be made now (writers wait);
  - issues/rotation-keyset-gone-before-its-boxes.md and the made-up-keyset limit.

  One case to confirm before deleting it: a party removing its own route (D0_half, f removes S from M and rotates M). Without Possession that rotation is valid, and f keeps the epoch it made until another rotator of M acts. That is the self-removal rule ("cuts off nothing by itself"), not a new leak, but it should be checked against that rule.
- Bends: Blocked through holder actors and the mark are unchanged; they are key rules.
- Privacy: A's nodes, readers included, learn each demotion of a writer or admin anywhere below a member that holds write or above on A: who, from which group, by whom, and the frontier's commit IDs. They learn nothing of readers' removals or current rosters. A's nodes already see every author's chain into member groups. What is new is the demotions of writers who never acted on A. Example: members of a company-wide channel learn that someone lost editor rights on a team nested in it.
- Metadata: one demotion ID per demotion in the keyset that first covers it (usually none). A demotion's certificate is placed under each label above M where M holds write. That matches what Placing revokes already places, but with a carrier that always arrives.
- Liveness: nothing new waits on a party. A keyset whose demotions are withheld counts as not yet arrived, which is the existing Carried limit.
- Complexity: one keyset field, one placement rule, one holding rule. Removes Possession.

### C. Full transparency
Every node of a parent syncs its members' rosters at every depth, or, in the version Tess's study avoided, holds members' keys.
- Leaks: closed, since the removal is always known. With rosters, Seal could also judge departures below by order, and the mark might go.
- Privacy: worst. Every ancestor's nodes see every nested roster, readers included. With keys, a parent's admins read member groups' content, which is unacceptable.
- Liveness: unchanged. Cost: every ancestor node syncs the role history of the whole subtree. Complexity: the departure walk below the actor, the first-level cost notes/keys-requirements-study.md rejected.

### D. Keyset metadata down the proof chain (option 2 of the removed-member issue)
G's rotations carry X2's keyset commits (metadata only) so G's admin sees X2's knowing keyset.
- Leak 1 closes only into a stall. W's keyset of X1 proves X2 at a keyset A now finds stale, so Seal leaves X1 out of G. Nothing past W's keyset ever comes, because B holds it invalid. So X1 stays out until X1 rotates for some other reason.
- The made-up and backdated leaks still need the unjudged-proof rule (`AsOf`). The depth0-forged-box study rejected it: a rotation per honest race, and a cascade that leaves X1 out for good.
- Not recommended.

## Model
core/test/tla/rotation/Depth0.tla:
- `Travel`: a keyset carries the removals of writers through holder actors and of admins, below its actor, that its rotator held. A node holds it only with them.
- `Possession`: a switch for the possession rule.
- `Rogue`: W rotates X1 past the knowing keyset, then G.
- `NoLeakKnowing`: the requirement as written. A writer holding a keyset of each holder actor whose rotator knew the removal writes nothing the removed device opens. `NoLeakLimit` misses the rogue path, as the spec's "descending from a knowing rotation" does.

`D0_rm_possess0` still passes. Shape G {a1, X1}, X1 {b, X2}, X2 {b, W}; b removes W from X2 and syncs only X1 and X2; a1 syncs only G. Single worker, at load 10-20.

| cfg | Travel | Possession | result |
|---|---|---|---|
| `D0_rm_made` / `D0_rm_back` | no | yes | fail `NoLeakLimit` (made-up, backdated) |
| `D0_rm_rogue` | no | yes | fail `NoLeakKnowing` (W rotates X1, 1,432 states) |
| `D0_rm_np` | no | no | fail `NoLeakLimit` (W seals X1's new keyset) |
| `D0_rm_made_travel` / `_back_travel` | yes | yes | pass (8,254 / 8,230 states, 41 s) |
| `D0_rm_rogue_travel`, `_np` | yes | yes / no | pass (61,587 states, 13 / 7 min) |
| `D0_rm_np_travel` | yes | no | pass (8,230 states) |
| `D0_rm_made_travel_np` / `_back_travel_np` | yes | no | pass |
| `D0_rm_np_travel_live` | yes | no; liveness | no violation, unfinished (434 states in 10 min; fairness over this shape is slow) |

Probes confirm that the attack epoch is written under and that the knowing premise is reached (`ProbeAttackWrite`, `ProbeKnowingWrite` fail as expected). No stall by construction: Travel only adds knowledge, which only makes a writer's keysets invalid and a rotation due; nothing waits for it. Not modelled: withheld demotion certificates (taken as the keyset not arriving), compaction, several roles, and the self-route case above.

## For Tess
1. **Privacy**: may a parent's nodes, readers included, learn the demotions of writers and admins inside member groups at any depth, though not readers' removals or rosters? This is the cost of B. spec/requirements.md Permissions says "A never depends on who they are". B keeps that for A's own records (no write on A is needed), but A's nodes learn these demotions.
2. **Requirements limit**: with B, nothing widens. The holder-actor limit holds as written, and the crypto limits shrink to "until M's knowing keyset reaches A's writers". Option A would instead widen the limit to "until the removal reaches A's writers", with no bound in the shape where the removed writer is the only bridge.
3. If B, Possession goes in a follow-up, after the self-route case is checked against the self-removal rule.
