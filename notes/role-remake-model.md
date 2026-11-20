# Making role writes again (`Rules::remake`)
> Summary: The proposal for role writes a removed party made that its remover never received: no vouch; a witness that holds the right makes the write again as its own. Modelled in roles-model `paths` beside today's rule (`Rules::fixed`, vouches); its rule set, the generator's witness-lowering moves, each gate's result under both, what users lose, and the questions for Tess. A proposal: nothing here is in spec or the drafts.

## Principle
A role write is judged only by its own signer's path at its own key. Nothing speaks for another's role write: a witness that wants X's write to stand writes it again, signed by itself, judged like any write of its own. A contested witness is then an ordinary admin fight, shown as a dispute and decided by trust.

Why: a vouch for a role write cannot be kept to its promise. Two worlds with the same held commits need opposite answers (`the_pair_under_the_vouch_reads_the_thiefs_side_unshown`): X removed N5 at 3, only B received it, H removed X listing nothing, and N5's key backdates a removal of B to 2; the same commits are the honest world where N5 removed a stolen B and the thief, with X's and B's keys, backdates X's removal of N5 and B's answer. Any rule over the held set is wrong in one of them; today's reads the thief's side where H's removal is trusted, unshown. A rule that counts the witness's word must count it by the witness's standing, and a backdated lowering of the witness contests that standing.

## The rule set
roles-model README.md, Paths, Making again, states it as definitions (`Rules::remake`, `Sim::remake_at`). In short:
- **Reader**: `Vouch::Off`. A vouch part is inert (held, it does nothing). Chosen over "bad input" because nothing has to detect it and the commit's other parts are untouched.
- **Writer**: an honest node, for each honest removal r it holds and did not sign, makes again each edge write c resting on r's edge that it received by r's `ts`, r does not list, its walk does not show, nothing later replaced, still gives something, and lowers no edge of its own side's remover. The write is its own, along its own path, with c's value, listing what it had received resting on c's edge when c reached it; it writes only where its own walk (the write held and trusted) applies it and r. A write whose re-making would be a self-removal is not made again (a leave audits nothing, finding 14). The remover makes nothing again.
- **Trust**: honest nodes trust the honest removals and the honest writes made again that lower their edge.
- **Who can**: any node holding admin on c's thing in its own walk; a victim cannot make its own lowering again; nobody can make X's writes on X's own removed edge (r sets it).

Rejected: the remover making again what reaches it after its removal (the study's wording): nothing then shows it was made in time, so the thief's backdated writes would be made again for it.

## Generators
The story's thief never lowered a witness, so 400,000 worlds passed a rule two hand commits break. Added: `Setup::n5` 4 (X's removal of N5 reaches B in time and H only at the settle), moves 53 to 60 (N5's key removing or demoting B before X's removal of N5; X's backdated removal of B with N5's vouch for it; X removing or demoting B backdated; X removing K from A2; a made-up key, by X's or N5's key, removing B after the theft). Not added: lowerings of a witness heard before the removal (the remover lists them: they stand by design), and the pair's honest mirror in the story (B's key is never the thief's there; the hand worlds hold it). Replay one world: `cargo run --bin roles-model -- I paths-replay[-remake]` (random world I; `paths-exh-replay` a family world); a run prints the first failing world indices per check; `-- N paths-compare` runs both rule sets on each random world and splits each failing check by rule set and by generator part.

## Results
Story, 400,000 random worlds and every 367th family world (30,637), each rule set with the same menu; check failures counted per node (roles-model README.md, Paths). Failing worlds split by `-- 40000 paths-compare` (run before the rebase over main's vouch counting change, which moved the story counts by under 0.2%).

| gate | `fixed` 400,000 / family | `remake` 400,000 / family |
|---|---|---|
| safety | 53,224 / 1,596 | 93,576 / 4,851 |
| liveness | 107,851 / 8,031 | 39,411 / 4,506 (the weaker one below) |
| removal (no trusted removal void) | 19,503 / 794 | 7,237 / 417 |
| own path | 13,176 / 444 | 5,874 / 366 |
| idle gains | 5,780 / 0 | 3,127 / 0 |
| dispute | 5,282 / 196 | 3,112 / 126 |
| safety N | 729 / 74 | 3,308 / 340 |
| admin, purge, removal kept, own path N | 350, 90, 38, 14 | 159, 27, 0, 4 |
| quiet, one reading, alike, self-taken, settles | 0 | 0 |

**`fixed` (today's rule)**: no failure on the earlier menu (40,000 compared worlds); every failing world holds `Setup::n5` 4 or a move 53 to 60. The measure of today's exposure: wherever a key X lowered unreceived (N5) fights a witness or the remover, the vouch decides silently for the thief. Smallest worlds: the pair (`the_pair_under_the_vouch_reads_the_thiefs_side_unshown`: N5 an admin, B removed, no dispute where H's removal is trusted); N5's key vouching for X's demotion of H that H heard (story world 290, `-- 290 paths-replay`: H's trusted removal void, X an admin; `remake` holds it); move 55 (two thief commits cancelling B's vouch). Of 40,000 compared worlds, failing safety under `fixed` alone 381, under `remake` alone 702, under both 167; liveness 278 / 364 / 181; removal (trusted removal void) 202 / 8 / 127.

**`remake`**: required gates under it, stated:
- Safety (at trusting nodes nothing by a key that never held the right, or by X after its removal, shows; N5's key counts as removed only where H held X's removal of N5 or a witness that could make it again received it in time): fails. Every failing world holds `Setup::n5` 4: the only witnesses of X's removal of N5 are B and N5's own device, and either B lost its right before writing (`two_witnesses_race_and_neither_order_makes_both_writes_again`: N5's device, an admin in its own walk, makes X's demotion of B again first; story worlds 75, 540, 601) or N5's device is the only one left and its leave makes nothing again (`a_demotion_only_its_victim_received_is_lost_under_remake`; story world 385). Today N5's device vouches for its own removal and B's vouch reads B's right with X's writes dropped, so both pass there.
- Liveness, weaker: a role write X made before the removal, unlisted, that an honest node able to make it again (admin of its thing in its own walk, its path not ending at the holder) received in time shows by that node's write made again (from then on), unless a later honest write replaced it or the node does not sync its thing. Everything else as today, but writes that show only where the removal had listed every role write a witness received in time are counted, not failed (`lost: written under a role write before it was made again`: 151,450 node checks; content K wrote under a share counts back and does not appear there). Fails in the same `n5` 4 worlds as safety, plus 4 of 40,000 worlds where an invite X gave under its own share is lost (counted shape, missed by the counting: story worlds 13844, 19387).
- One reading, alike, quiet (re-makes in honest histories are shown as no dispute: 92,174 checks), settles, self-taken: hold.
- Disputes at nodes trusting nothing: the pair's two worlds are each shown, and trusting the witness's write gives world 1's reading (`the_pair_under_remake_is_an_ordinary_fight_shown_to_both_worlds`); story failures are again `n5` 4 worlds.
- Small worlds (`tiny`): read alike under both rule sets (no vouch, no story writer: `tiny_worlds_read_alike_under_remake`), so not rerun.

Both fail where a removed key's backdated lowering drops a witness's earlier write for good (Found on the way).

## What users lose under `remake`
Each with its hand world (roles-model `src/paths/tests.rs`); "today" is `fixed`.
1. **A share, grant or pairing X made that the remover never received exists again only from when a witness makes it again.** Content written under it counts back to X's grant (the re-grant rule). Role writes made under it in between (an invite the grantee gave) stay dropped unless their own authors make them again: `a_share_made_again_counts_content_back_and_drops_role_writes_made_under_it`. Today: all restored.
2. **A write a later honest write replaced before anyone made it again is never made again**, and what it gave in between is lost: X shared T1 with A2, K wrote through it, B removed A2 later listing K's write: K's write is lost (`a_share_a_later_honest_removal_replaced_is_never_made_again_and_its_window_is_lost`). Today: kept.
3. **A lowering only its victim received is lost**: the victim's own leave audits nothing, so it does not make the lowering again; the victim stays as it was (`a_demotion_only_its_victim_received_is_lost_under_remake`). Today: the victim's vouch keeps it. Where the victim is a stolen key's device (N5 in `Setup::n5` 4) and every other witness lost its right, the thief's earlier writes with that key stand.
4. **Witnesses race.** X removed N5 and demoted B; both received both; whichever writes again first takes the other's right, and neither order makes both again (`two_witnesses_race_and_neither_order_makes_both_writes_again`). The readings stay one function of the held set, but which of X's writes survive depends on which device wrote first: an incidental dependence. Today: B's vouch (its right read with X's writes dropped, the reading the study showed unsafe) keeps both.
5. **A removal only a non-admin received is lost**: nobody can make it again; the removed party is back until an admin removes it again, and only that non-admin's device knows. Today the same: only an admin's vouch counts.
6. **Between the removal and the write made again** the lowered party is back at nodes holding the removal and not yet the witness's write. Today the same window waits for the vouch.
7. **A timed grant whose end passed before it is made again** is not made again.
8. **Attribution**: the write made again is the witness's ("B granted Q"), in history and for removal: removing B later without listing it drops it. Today B's vouch falls the same way, and the write shows as X's.

Gained: a contested witness is shown as a dispute and decided by trust, where today it is decided silently for the thief's side (`the_pair_under_remake_is_an_ordinary_fight_shown_to_both_worlds`); finding 39's thief holds nothing (`finding_39s_thief_holds_nothing_where_a_witness_makes_the_removal_again`); a vouch from a key X lowered unreceived cannot void the remover's removal (story world 290: `-- 290 paths-replay` fails, `-- 290 paths-replay-remake` holds).

## Content addenda
An addendum vouches for content by its writer's standing at its position, and a backdated lowering of that writer contests it, so addenda have the pair's shape, but only through the role layer: a content write lowers nobody, so a thief holding only content cannot contest a witness. Whatever settles the witness's role (today's vouch, a write made again, the trust set) settles its addenda (`an_addendum_is_contested_only_through_its_witness_standing`): under the vouch the honest content is lost silently where the witness's vouch fails; under `remake`, trusting the witness's write made again keeps it, and not trusting it shows the dispute. No content analogue of making again is needed (it would change authorship); addenda stay.

## Found on the way (both rule sets)
- A key removed before the theft, its removal held by everyone, backdates a lowering ordered before its own removal: it applies at its key, drops the honest writes on the lowered edge, and those drops stand after its removal drops it (issues/removed-key-backdated-drop.md, `a_removed_keys_backdated_lowering_drops_a_witness_write_for_good`).
- The story's honest re-grants were written before the answers of earlier ticks existed, so their frontiers missed them; they are now written in tick order.

## For Tess
1. X removed someone, only another device saw it, then X is removed. Is it acceptable that the removal is not kept automatically: that device's owner, if an admin, removes the party again (its device does it unasked), and if the lowered party's key fights back the user sides on a shown dispute? If no admin saw it, nobody can: the party is back until someone notices.
2. X shared something or paired a device, and the remover had not received it. Is it acceptable that it exists again only from when another admin's device makes it again, content written under it counting again but invites and role changes made under it in between lost?
3. A device writing role changes in its user's name without being asked ("B granted Q", "B removed N5"): acceptable, or must the user confirm each? Today devices already write vouches unasked, but those show as X's writes.
4. A removal only its victim's device saw (or where another witness's write made again took the right first) is lost under `remake` and kept today. Accept, or is there a requirement here that the model cannot meet either way?
5. If any answer is no: which of the pair's two worlds should the model get wrong, and for whom?
