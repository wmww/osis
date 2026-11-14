# Networking rework model (TLA+)
> Summary: TLC models of the networking rework before it is built (issues/sync-rewrite.md). `NetStream.tla`: node-wide log, cursors, Pull, joins, Lost, restarts, record loss, restored or copied stores, deletion expiry, `Synced`. `NetShared.tla`: beacon filters, generations, pending set, Hit and tag, ByRole, Lost, the digest, rotations and removals on one side. `NetBlind.tla`: a peer that cannot read. `NetOpen.tla`: the open rule (issues/sync-rewrite.md): each side opens S only on its own proof judged on what it holds now (J, the sync-key proof, an open signature by a credential key of the newest step it knows, bound to the signer's side), re-judged at every grant, removal and rotation it learns; readers, stores keeping S unread and link holders. `NetHold.tla`: hold, log and delete per sync ID (spec/sync-judgement.md §2-§4, spec/sync-compaction.md §1). `NetDestroy.tla`: destruction and emptying (spec/sync-judgement.md §5). `NetKeep.tla`: a node keeping S unread following its own grant and its signed removal notice (spec/sync-judgement.md §6). Each rule of the design is a flag; turning it off finds a counterexample.

Files: `NetStream.tla`, `MCStream.tla`, `NetShared.tla`, `MCShared.tla`, `NetBlind.tla`, `MCBlind.tla`, `NetOpen.tla`, `MCOpen.tla`, `NetHold.tla`, `MCHold.tla`, `NetDestroy.tla`, `MCDestroy.tla`, `NetKeep.tla`, `MCKeep.tla`; cfgs `S_*` / `SN_*` (stream), `T_*` / `TN_*` (shared), `B_*` / `BN_*` (cannot read), `O_*` / `ON_*` (opens), `H_*` / `HN_*` / `HL_*` (hold), `D_*` / `DN_*` (destroy), `K_*` / `KN_*` / `KF_*` (keep); `*N_*` are rule removals, which must fail; `HL_*` shows a limit the spec states; `KF_*` is a finding's rule before the fix, which must fail (Findings below). Each cfg's first line says what it checks and why a failing one fails. `ASSUMPTIONS.md`: what is abstracted.

## Run
`tools/heavy env TMPDIR=<dir on disk> TLC_WORKERS=12 ../run.sh netstream`, `netshared`, `netblind`, `netopen` from this directory (`run.sh` puts TLC state in `TMPDIR`: never tmpfs). `netopen` runs in about a minute at one worker, no lock needed. `O_rk3.cfg`, `O_kk3.cfg`, `O_rx3.cfg`, `O_pub3.cfg` (three connections, safety only), `S_members.cfg`, `T_rot.cfg`, `T_untildrop.cfg`, `T_rotdrop.cfg`, `T_followremdrop.cfg` by name (under a few minutes each at 12 workers). `nethold` (63 s), `netdestroy` (13 s) and `netkeep` (8 s) at one worker need no lock; `H_host2.cfg` by name (64 s at 12 workers).

## Principle
A record says only what need not be sent again: a connection first proves the two records agree (a digest of S, first each way), then sends what changed; nothing about data is inferred from absence: an entry leaves a node by a log event or a right holder's delete, a member leaves S by a `Lost` or a digest difference.

## Properties
- `NoWriteLost`: no node drops a write nobody deleted.
- `CaughtUpHolds`: a source judged caught up (L open, last pull reached its end, nothing announced since) holds nothing of L this node lacks, unless deleted somewhere.
- `DeletionsArrive`: a deletion the source's log still holds reaches a node caught up with it.
- `ServedRight`: nothing is served for a sync ID the peer has lost the right to.
- `ReconnectCost`: a from-the-start reply happens only if the record is gone or the store is a restored or copied one; a restart and a long absence never force one.
- `Settles`: the connection settles (liveness).
- `RuleHolds`: when quiet, L is open on both sides or neither, exactly when each side's rule holds on what it holds now.
- `UntilEnds`: when quiet, no open rests on a proof a rotation made stale: the requester's report of passing `until` always arrives.
- `EpochReached`: a holder with L open on both sides at a rotation, no record lost, reaches the new epoch.
- NetOpen: `Safe` (no honest node opens S toward Adv unless the roster it knows lists Adv or Adv holds the seed of the newest step it knows: none toward a removed holder once it knows the rotation, none toward a node holding only S's public values; Adv replays any token it was sent), `SafeRm` (a removal ends at once: no reader opens toward Adv once it knows Adv's removal, rotation or not), `Live` (two honest holders on one connection, every event known to both, end up open both ways, whichever dialed; weak fairness of honest steps).
- NetHold (readers r1, r2 writing S; K keeping S unread; optionally H, a hostile writer deleting at K; b a write by r2, c r1's snapshot covering it, x r2's role commit making c invalid; r2 keeps b under c as local data, its entries out of r2's log): `Bounded` (no loop: per reader and body at most one logging again per change of ground, K's head or a fall of c there), `Carried` (no honest delete takes b while K, not full, holds no c), `NoLoss` (a needed body is held by an honest reader or K), `QuietAlike` (no H, quiet: every reader reads b's write and K holds every needed body), `Settles` (liveness: quiet is reached and stays), `NoCap` (the run's encryption bound was not what stopped a loop).
- NetDestroy (readers a, b with the delete key, K; a releases T by request q, whose expiry ends the window; b optionally away for it): `ToldBeforeEmptied` (no content entry is deleted at K inside the window while K holds no q), `NoMiss` (a node reading K inside the window is told), `ForgetEmpty`, `Bounded` (no step-against-each-other loop), `QuietDone` (a node present in the window ends without T), `Settles`.
- NetKeep (a forger sends a notice signed by no delete key of S; the granter may re-grant K once after removing it): `NoDropOnHeadMove` (K's store goes only by a genuine removal notice or an unlisting: never on a head move, a forged notice, or its removal's notice once it holds its re-grant), `RemovedStops` (K opens S at no step past its removal), `StrandedOnlyWaiting` (K is stranded only while its box is on its way, or once removed and before its re-grant), `RemovedDrops` (a removed K whose notice and Registers all arrived keeps S no more).
- NetBlind: `Carried` (a delete never takes a body whose covering snapshot the peer does not hold), `Placed` (quiet: the peer holds what the reader holds live), `DeletesReach` (quiet: the peer holds nothing the reader covers).

## Results
TLC 2.19, 12 workers. Positive cfgs pass; each `*N_*` fails with the listed property.

| cfg | scenario | result | states |
|---|---|---|---|
| S_loss | restart, record loss, delete, expiry, drop | pass | 2,784,021 |
| S_restore | b restored from a backup taken at any instant | pass | 4,563,347 |
| S_copies | b and its restored copy both live, one pair key | pass | 3,335,072 |
| S_join | a second sync ID joins a running stream, paged | pass | 1,379,328 |
| S_oneway | only the far side can dial | pass, `Settles` | 12,019 |
| S_live | settles after restart and drop | pass, `Settles` | 27,461 |
| T_cred | two nodes, one credential, no role knowledge | pass | 2,944 |
| T_gain | a credential gained while connected | pass | 167,734 |
| T_remove | role removed, learned on one side, drop | pass | 338,593 |
| T_recloss | record lost on one side | pass | 58,572 |
| T_copies | filter generations with two live copies | pass | 88,277 |
| T_hostile | peer answers any Hit, claims every credential | pass | 1,366 |
| T_until | rotation event served before Lost | pass | 56,378 |
| T_follow | rotation with `follow`: only a Push marked `report` is answered | pass | 35,709 |
| T_followdrop | ... and a drop after the rotation | pass | 200,819 |
| T_followrem | ... with a removal | pass | 2,077,037 |
| T_live | settles, with a rotation | pass, `Settles` | 400,494 |
| T_untildrop | rotation then a drop (by name, bounded) | pass | 200,788 |
| T_rot | rotation and removal (by name, bounded, no drop) | pass | 2,110,348 |
| T_rotdrop | rotation, then a drop, ByRole on, no removal (by name, bounded) | pass | 2,247,546 |
| T_followremdrop | follow, rotation, removal, a drop (by name, bounded) | pass | 21,720,953 |
| S_members | role gained and lost mid-connection, rejoin from lag (by name) | pass | 19,360,038 |
| B_all | a peer that cannot read: drop, backup restore, record loss | pass | 4,185 |
| B_live | settles | pass, `Settles` | 486 |
| O_rk | a reader, a store granted later; Adv an account member, removed, then a rotation; 2 connections (the module: about a minute at one worker) | pass, `Live` | 29,568 |
| O_kk | two stores; Adv removed, rotation; 2 connections | pass, `Live` | 16,138 |
| O_rx | a reader, a link holder; Adv a link holder, removed, rotation; 2 connections | pass, `Live` | 11,642 |
| O_pub | a reader, a store, a rotation; Adv holds only public values; 2 connections | pass, `Live` | 6,763 |
| O_rk3 | as O_rk, 3 connections (by name, safety) | pass (79 s at 12 workers) | 1,535,112 |
| O_kk3 | as O_kk, 3 connections (by name, safety) | pass (26 s) | 908,386 |
| O_rx3 | as O_rx, 3 connections (by name, safety) | pass (28 s) | 548,490 |
| O_pub3 | as O_pub, 3 connections (by name, safety) | pass (22 s) | 387,795 |
| H_quiet | two readers, K, x; the spec's rules | pass | 1,661 |
| H_head | ... a head move at K | pass | 9,510 |
| H_meet | ... readers also pull each other | pass | 3,659 |
| H_full1 | K full with room for one, tombstones expiring | pass | 1,693 |
| H_full2 | room for two, with x | pass | 1,501 |
| H_expire | tombstones expire | pass | 44,009 |
| H_host | H deletes once | pass | 210,327 |
| H_host2 | H deletes twice (by name, 64 s at 12 workers) | pass | 5,971,488 |
| H_live | settles: head move, room for two, expiry | pass, `Settles` | 69,439 |
| HN_standhead, HN_snap | stand ground without the head; no unheld-snapshot clause | pass (not needed by any property here) | 7,002, 1,786 |
| D_present, D_away | destruction, b present / away for the window | pass | 210, 770 |
| D_live, D_live2 | settles | pass, `Settles` | 770, 210 |
| K_all | rotations, removal, a forged notice, unlisting, any arrival order (head-only signature rule) | pass | 1,179 |
| K_held | ... re-grants, the spec's rule (the fixes of `KF_late` and `KF_regrant`), with `RemovedDrops` | pass | 5,328 |

Rule removals: `SN_infer_lit`, `SN_infer_knew` NoWriteLost; `SN_history` ReconnectCost; `SN_listdels` DeletionsArrive; `SN_inc`, `SN_copies`, `SN_sreconcile`, `SN_joindur`, `SN_joinans`, `SN_lostolder`, `SN_cursor`, `SN_rearm` CaughtUpHolds; `SN_gate` ServedRight; `SN_bothpull` Settles; `TN_pending`, `TN_ack`, `TN_untilack`, `TN_arrival`, `TN_tag`, `TN_genbase`, `TN_byrole`, `TN_reconcile`, `TN_retest`, `TN_decline`, `TN_offergate`, `TN_reptested` RuleHolds; `TN_until` EpochReached; `TN_report`, `TN_cursorrep` UntilEnds; `BN_upack`, `BN_whole` Placed; `BN_cover` Carried; `BN_known` DeletesReach; `ON_side` (no side byte: a store's own signature reflected as Adv's answer), `ON_answer` (a Hit on a public sync key opens without an answer), `ON_old` (an older step's sync key counts: a store's open by Adv's step-0 key outlives the rotation), `ON_proofpub` (the proof from the public sync key: Adv computes the new step's), `ON_proofold` (an older step's proof counts), `ON_linkold` (a static entry an older roster listed counts: Adv Hits its removed entry left in a stored filter), `ON_jnow` (J from the roster the node started with), `ON_endj`, `ON_endsync`, `ON_endproof`, `ON_endlink` (an open on that basis not re-judged when the node learns a removal or rotation: it outlives it), `ON_dialer` (the dialer opens toward the key it dialed) Safe; `ON_departed` SafeRm; `ON_nolisten` (listeners never sign: a reader dialed by a link holder cannot sign its answer) Live.

Finding (`ON_departed`): the rule as stated (J, a secret shown, or a newest-step signature) does not make a removal end opens at once. A reader that knows Adv's removal but not yet its rotation still accepts Adv's sync-key signature or proof of the current step (Adv still holds that seed) and opens again; J ending at once changes nothing. The design's admissibility clause (a credential of a peer J judges departed counts only at a step covering every departure; inputs, area 3, Admissible credential) closes it: `Departed`, on in every positive cfg. Stores hold no roster: they open toward a removed holder until they learn the rotation, which `Safe` allows (until then the holder holds the current seed anyway).

Rule removals: `HN_stand` Bounded (log-liar loop); `HN_standfall`, `HN_fallany` (only a fall of a held part ends the stand: a node that got c already invalid keeps standing), `HN_fresh`, `HN_rolefirst`, `HN_delview` (a delete does not wait for a role commit K's stream shows), `HN_invalid` (a snapshot judged invalid still counts against established uncovered), `HN_full` QuietAlike; `HN_ownlog` (the author keeps its covered body in its log: K pulls it back at each tombstone expiry and it is deleted again) Settles; `HN_known` Carried; `HN_readers` NoLoss; `DN_req` (emptying deletes the destroying request: a node reading K inside the window misses it) ToldBeforeEmptied, NoMiss; `DN_told` ToldBeforeEmptied; `DN_stand` Bounded (released-team storm); `DN_forget` ForgetEmpty; `KN_drop` (a head move drops the store), `KN_sig` (a removal notice's signature unchecked: the forged one drops it) NoDropOnHeadMove; `KN_open` RemovedStops.

Limit (`HL_capjunk`, spec/sync-judgement.md §3 Deletes): an invalid body is never deleted at peers (spec/permissions.md §6), so at a full store it holds room a needed body is refused for, until expiry or the caps give way; QuietAlike fails.

## Findings
- `KF_late` (adopted in spec/sync-judgement.md §6 Stops; `KF_late.cfg` keeps the head-only rule failing): a removal signature is by the delete key of the newest step its sender records (spec/wire.md §9 position 5), and K checks it only under its head's. A remover writes the removal before the rotation's step exists, so its notice is signed by step e; Register needs no open and any node relays it, so K can take step e+1 before its inbox brings the notice. K's head is then past e for good (it is stranded at e+1 and later steps only move it on), the notice never verifies, and K keeps S's ciphertext for ever although an admin signed its removal. Trace (MaxEp 1): the granter removes K and rotates, notice signed at step 0; K takes the Register of step 1; the notice arrives and is held, never verifying. The rule: the signature verifies under the delete key of any step of K's path from the newest step whose sync secret K holds to its head (while not stranded that is the head alone, so a forger gains nothing over today's rule: one holding the head's delete key is accepted either way). `K_held` passes with it, every property kept.
- `KF_regrant` (adopted in spec/sync-judgement.md §6 Stops and spec/wire.md §9 position 5; `KF_regrant.cfg` keeps the unbound signature failing): K removed at epoch e and re-granted at e+1 takes the re-grant's box before step e+1 is registered; the removal's notice, signed at step e, then verifies at the newest step K holds a secret of, and K shreds the re-granted copy and drops its record. Trace (MaxEp 1): removal and rotation, notice signed at step 0; re-grant boxes epoch 1; K takes the box, then the notice. The rule: a removal signature binds the newest sync epoch its sender boxed the recipient at, and K takes it only at or past every sync epoch it holds. `K_held` passes with it.
