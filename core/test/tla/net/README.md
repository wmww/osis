# Networking rework model (TLA+)
> Summary: TLC models of the networking rework before it is built (issues/sync-rewrite.md). `NetStream.tla`: node-wide log, cursors, Pull, joins, Lost, restarts, record loss, restored or copied stores, deletion expiry, `Synced`. `NetShared.tla`: beacon filters, generations, pending set, Hit and tag, ByRole, Lost, the digest, rotations and removals on one side. `NetBlind.tla`: a peer that cannot read. `NetOpen.tla`: the open rule (issues/sync-rewrite.md): each side opens S only on its own proof judged on what it holds now (J, the sync-key proof, an open signature by a credential key of the newest step it knows, bound to the signer's side), re-judged at every grant, removal and rotation it learns; readers, stores keeping S unread and link holders; a store granted later shows its grant's step's sync key and proof with no step, and a reader registers its genesis there once S is open (spec/sync-opens.md §4 Admissible, spec/sync-ids.md §6 Walk). `NetHold.tla`: hold, log and delete per sync ID (spec/sync-judgement.md §2-§4, spec/sync-compaction.md §1). `NetDestroy.tla`: destruction and emptying (spec/sync-judgement.md §5). `NetKeep.tla`: a node keeping S unread following its own grant, dropping its copy at a head past its keys (spec/sync-judgement.md §6). Each rule of the design is a flag; turning it off finds a counterexample.

Files: `NetStream.tla`, `MCStream.tla`, `NetShared.tla`, `MCShared.tla`, `NetBlind.tla`, `MCBlind.tla`, `NetOpen.tla`, `MCOpen.tla`, `NetHold.tla`, `MCHold.tla`, `NetDestroy.tla`, `MCDestroy.tla`, `NetKeep.tla`, `MCKeep.tla`; cfgs `S_*` / `SN_*` (stream), `T_*` / `TN_*` (shared), `B_*` / `BN_*` (cannot read), `O_*` / `ON_*` (opens), `H_*` / `HN_*` / `HL_*` (hold), `D_*` / `DN_*` (destroy), `K_*` / `KN_*` (keep); `*N_*` are rule removals, which must fail; `HL_*` shows a limit the spec states. Each cfg's first line says what it checks and why a failing one fails. `ASSUMPTIONS.md`: what is abstracted.

## Run
`tools/heavy env TMPDIR=<dir on disk> TLC_WORKERS=12 ../run.sh netstream`, `netshared`, `netblind`, `netopen` from this directory (`run.sh` puts TLC state in `TMPDIR`: never tmpfs). `netopen` runs in about 5 minutes at one worker (box load 16), no lock needed. `O_rk3.cfg`, `O_kk3.cfg`, `O_rx3.cfg`, `O_pub3.cfg` (three connections, safety only), `S_members.cfg`, `T_rot.cfg`, `T_untildrop.cfg`, `T_rotdrop.cfg`, `T_followremdrop.cfg` by name (under a few minutes each at 12 workers). `nethold` (95 s), `netdestroy` (12 s) and `netkeep` (10 s) at one worker need no lock; `H_host2.cfg` by name (64 s at 12 workers), `S_pres.cfg` by name (89 s at 12 workers).

## Principle
A record says only what need not be sent again: a connection first proves the two records agree (a digest of S, first each way), then sends what changed; nothing about data is inferred from absence: an entry leaves a node by a log event or a right holder's delete, a member leaves S by a `Lost` or a digest difference.

## Properties
- `NoWriteLost`: no node drops a write nobody deleted.
- `CaughtUpHolds`: a source judged caught up (L open, last pull reached its end, nothing announced since) holds nothing of L this node lacks, unless deleted somewhere.
- `CaughtUpServed` (spec/sync-status.md §1, both halves): caught up also needs the peer to have pulled this node's stream to its end and Applied it, nothing left to push; then the peer holds what this node holds, unless deleted somewhere.
- `PresenceSound` (`TrackPres`; spec/sync-judgement.md §3 `known`): caught up with a source, nothing this node holds as present there is missing there.
- `DeletionsArrive`: a deletion the source's log still holds reaches a node caught up with it.
- `ServedRight`: nothing is served for a sync ID the peer has lost the right to.
- `ReconnectCost`: a from-the-start reply happens only if the record is gone or the store is a restored or copied one; a restart and a long absence never force one.
- `Settles`: the connection settles (liveness).
- `RuleHolds`: when quiet, L is open on both sides or neither, exactly when each side's rule holds on what it holds now.
- `UntilEnds`: when quiet, no open rests on a proof a rotation made stale: the requester's report of passing `until` always arrives.
- `EpochReached`: a holder with L open on both sides at a rotation, no record lost, reaches the new epoch.
- NetOpen: `Private` (Adv holding no value of S: no Lost names S to it), `Safe` (no honest node opens S toward Adv unless the roster it knows lists Adv or Adv holds the seed of the newest step it knows: none toward a removed holder once it knows the rotation, none toward a node holding only S's public values; Adv replays any token it was sent), `SafeRm` (a removal ends at once: no reader opens toward Adv once it knows Adv's removal, rotation or not), `Live` (two honest holders on one connection, every event known to both, end up open both ways, whichever dialed; weak fairness of honest steps).
- NetHold (readers r1, r2 writing S; K keeping S unread; optionally H, a hostile writer deleting at K; b a write by r2, c r1's snapshot covering it, x r2's role commit making c invalid; r2 keeps b under c as local data, its entries out of r2's log): `Bounded` (no loop: per reader and body at most one logging again per change of ground, K's head or a fall of c there), `Carried` (no honest delete takes b while K, not full, holds no c), `NoLoss` (a needed body is held by an honest reader or K; c once x fell only if K ever held it), `QuietAlike` (no H, quiet: every reader reads b's write, holds c when needed and b when kept, and K holds every needed body), `Settles` (liveness: quiet is reached and stays), `NoCap` (the run's encryption bound was not what stopped a loop).
- NetDestroy (readers a, b with the delete key, K; a releases T by request q, whose expiry ends the window; b optionally away for it; optionally a and b each other's sources): `ToldBeforeEmptied` (no content entry is deleted at K inside the window while K holds no q), `NoMiss` (a node reading K inside the window is told), `ForgetEmpty` (no forget while a source, K or a reader, shows an entry), `Bounded` (no step-against-each-other loop), `QuietDone` (every node ends without T: one present by emptying, one away by Untold), `Settles`.
- NetKeep (the granter may re-grant K once after removing it; the account may unlist and list again): `OnlyBoxedContent` (K holds content only of steps it was boxed at), `RemovedHoldsNothing` and `RemovedClosed` (removed, its head past the removal, K holds nothing and opens S nowhere), `FewStops` (K drops its copy a bounded number of times: no loop), `Refetches` (once quiet, a K boxed at the current epoch and listed holds the head's content: a late box or a re-grant re-fetches).
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
| S_pres | presence: deletes, expiry with trimmed replies, b restored from a backup (by name; `DeletionsArrive` off: a deletion the restored copy still logs lies below a cursor read past its expiry at b, the stated limit) | pass (89 s at 12 workers) | 4,597,182 |
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
| O_rk | a reader, a store granted later (showing its grant's step with no head; its genesis registered once open); Adv an account member, removed, then a rotation; 2 connections (about 60 s at one worker) | pass, `Live` | 36,472 |
| O_kk | two stores; Adv removed, rotation; 2 connections | pass, `Live` | 16,138 |
| O_rx | a reader, a link holder; Adv a link holder, removed, rotation; 2 connections | pass, `Live` | 11,642 |
| O_pub | a reader, a store, a rotation; Adv holds only public values; 2 connections | pass, `Live` | 6,763 |
| O_rk3 | as O_rk, 3 connections (by name, safety) | pass (127 s at 12 workers) | 1,942,392 |
| O_kk3 | as O_kk, 3 connections (by name, safety) | pass (26 s) | 908,386 |
| O_rx3 | as O_rx, 3 connections (by name, safety) | pass (28 s) | 548,490 |
| O_pub3 | as O_pub, 3 connections (by name, safety) | pass (44 s) | 387,795 |
| O_none | a reader, a store, a rotation; Adv holds no value of S and shows junk filter entries both Hit | pass, `Live`, `Private` | 25,883 |
| O_rkjunk | as O_rk, Adv's junk entries Hit too | pass, `Live` | 39,328 |
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
| H_keep | b kept (must-hold whatever covers it) | pass | 124 |
| H_xfall | x falls: c fetched back where dropped as invalid | pass | 22,447 |
| H_restart | readers restart, the stand durable, a head move | pass | 19,020 |
| D_present, D_away | destruction, b present / away for the window (away: untold, it forgets T) | pass | 210, 471 |
| D_live, D_live2 | settles | pass, `Settles` | 471, 210 |
| D_meet, D_meetaway, D_meetlive | readers also each other's sources; b away then untold; settles | pass | 1,020, 1,182, 1,020 |
| K_all | rotations, a removal, a re-grant, unlisting and listing again, boxes and Registers in any order | pass | 3,425 |
| K_nohead | ... granted before any step is registered (no head: shows every secret it holds), first box late | pass | 7,603 |
| K_fake | ... a hostile box of a self-made epoch: hides no key, keeps no removed copy | pass | 6,850 |

Rule removals: `SN_infer_lit`, `SN_infer_knew` NoWriteLost; `SN_history` ReconnectCost; `SN_listdels` DeletionsArrive; `SN_inc`, `SN_copies`, `SN_sreconcile`, `SN_joindur`, `SN_joinans`, `SN_lostolder`, `SN_cursor`, `SN_rearm` CaughtUpHolds; `SN_gate` ServedRight; `SN_bothpull` Settles; `SN_servehalf` (caught up from the pulling half alone), `SN_applied` (a reply served to the end counted before the peer's Applied) CaughtUpServed; `SN_trim` (no trimmed reply: a cursor below an expired deletion reads on, presence keeps the entry) PresenceSound; `TN_pending`, `TN_ack`, `TN_untilack`, `TN_arrival`, `TN_tag`, `TN_genbase`, `TN_byrole`, `TN_reconcile`, `TN_retest`, `TN_decline`, `TN_offergate`, `TN_reptested` RuleHolds; `TN_until` EpochReached; `TN_report`, `TN_cursorrep` UntilEnds; `BN_upack`, `BN_whole` Placed; `BN_cover` Carried; `BN_known` DeletesReach; `ON_side` (no side byte: a store's own signature reflected as Adv's answer), `ON_answer` (a Hit on a public sync key opens without an answer), `ON_old` (an older step's sync key counts: a store's open by Adv's step-0 key outlives the rotation), `ON_proofpub` (the proof from the public sync key: Adv computes the new step's), `ON_proofold` (an older step's proof counts), `ON_linkold` (a static entry an older roster listed counts: Adv Hits its removed entry left in a stored filter), `ON_jnow` (J from the roster the node started with), `ON_endj`, `ON_endsync`, `ON_endproof`, `ON_endlink` (an open on that basis not re-judged when the node learns a removal or rotation: it outlives it), `ON_dialer` (the dialer opens toward the key it dialed) Safe; `ON_departed` SafeRm; `ON_nolisten` (listeners never sign: a reader dialed by a link holder cannot sign its answer), `ON_shownkey` (a store with no step shows and tests nothing: the store granted later never opens S, and nothing registers its genesis there) Live; `ON_losttag` (a Lost on an acceptance without a valid tag: a tester Hits Adv's junk entry and the Lost names S to a peer holding no value of S) Private.

Finding (`ON_departed`): the rule as stated (J, a secret shown, or a newest-step signature) does not make a removal end opens at once. A reader that knows Adv's removal but not yet its rotation still accepts Adv's sync-key signature or proof of the current step (Adv still holds that seed) and opens again; J ending at once changes nothing. The design's admissibility clause (a credential of a peer J judges departed counts only at a step covering every departure; inputs, area 3, Admissible credential) closes it: `Departed`, on in every positive cfg. Stores hold no roster: they open toward a removed holder until they learn the rotation, which `Safe` allows (until then the holder holds the current seed anyway).

Rule removals: `HN_stand` Bounded (log-liar loop); `HN_standfall`, `HN_fallany` (only a fall of a held part ends the stand: a node that got c already invalid keeps standing), `HN_fresh`, `HN_rolefirst`, `HN_delview` (a delete does not wait for a role commit K's stream shows), `HN_invalid` (a snapshot judged invalid still counts against established uncovered), `HN_full` QuietAlike; `HN_ownlog` (the author keeps its covered body in its log: K pulls it back at each tombstone expiry and it is deleted again) Settles; `HN_known` Carried; `HN_readers` NoLoss; `DN_req` (emptying deletes the destroying request: a node reading K inside the window misses it) ToldBeforeEmptied, NoMiss; `DN_told` ToldBeforeEmptied; `DN_stand` Bounded (released-team storm); `DN_forget` ForgetEmpty; `DN_toldsrc` (told by a reader, a node deletes at K before K holds q) ToldBeforeEmptied; `DN_forgetall` (forget counting K alone, a reader source still listing e) ForgetEmpty; `DN_untold` (untold leaves S keeping T) QuietDone; `HN_mustdrop` (a kept body covered and dropped: K lacks it) QuietAlike; `HN_invaliddel` (c dropped as invalid deleted at K: once x falls c is gone everywhere) NoLoss; `HN_fixpoint` (r1 takes x and, before judging c invalid, deletes b's logged-again encryption at K under c; r2's stand holds, K lacks b) QuietAlike; `HN_durable` (a restart loses the stand: b logged again past a delete that stands) Bounded; `KN_keep` (keeps its copy at a head past its keys) RemovedHoldsNothing; `KN_open` (past its keys, shows every held secret) RemovedClosed; `KN_shownone` (past its keys, shows nothing: a re-grant after a further rotation is never registered onward) Refetches; `KN_take` (takes at a head past its keys: content stamped for a step after its removal while a re-grant's path climbs) OnlyBoxedContent; `KN_droppath` (a stop shreds the path too: with no head K shows its old secrets, the granter registers the path again, K stops again) FewStops.

Limit (`HL_capjunk`, spec/sync-judgement.md §3 Deletes): an invalid body is never deleted at peers (spec/permissions.md §6), so at a full store it holds room a needed body is refused for, until expiry or the caps give way; QuietAlike fails.

## Findings
- `SN_pres` (spec/sync-streams.md §4 Applying, open): the spec lets only a listing from the start marked `trimmed` replace what a requester holds as present at the source; any other listing from the start (a cursor naming no position at a restored or copied store, a join from the start) leaves stale presence. Trace (`SN_pres`, 13 states): a and b connected; a backup c of b is taken; b writes e2; a pulls it (e2 present at b); b is restored from c, keeping a's record; a's cursor names no position in c's history, so c answers from the start, not trimmed; the listing ends without e2 and a still counts e2 present there (it would count e2 held elsewhere while that store lacks it). Proposed fix (the coordinator's decision): "A listing never treats an absent entry as deleted, except that a listing from the start (trimmed, a cursor naming no position, or a join from the start), once complete, replaces what the requester holds as present there for its members." `S_pres` passes with it, `SN_trim` shows the trimmed half is needed too.
- Presence completeness at a restored store (stated limit, not a fix): an entry b deleted after a backup has its add event compacted away below a cursor a later reads at b; restored from that backup, the store holds the entry again under the same incarnation, and a's cursor, honoured there, never shows it. Only deleted entries come back so (compaction moves an event only on a deletion), so presence errs toward absent: data-safe, but a right holder never deletes the resurrected entry at a store keeping S unread until something lists it again. `PresenceSound` checks the safe direction only.

## Rules these models do not reach
- NetOpen, filter width and the additions count (spec/sync-opens.md §5): a filter is a set of values, not bits. A junk entry matching what a tester tests is modelled (`AdvJunk`) as always possible; width enforcement bounds how often, a rate the model does not express.
- NetStream, the rest of a partly answered Fetch asked before what came is applied (spec/sync-streams.md §4 Bodies): an event carries its entry; Fetch, bodies and fill order are out.
- NetOpen, when a side tests (spec/sync-opens.md §5 Testing: its own changes and re-marks): any Hit on a value shown is enabled at any time, so `Live` holds whichever side tests; that the store's own test finds a reader's shown proof once it keeps S is tested in core/sync (`opens::a_store_granted_later_opens_with_no_head_spec_sync_opens_4`).
- NetHold, first logging verbatim (spec/sync-judgement.md §3 Own store): with one sync ID, logging a held blob verbatim or as a fresh encryption differs only in cost; the author's entries returning to its log keep their blob IDs, and logging again is fresh (`HN_fresh`). Judgement per (S, commit, source) from that source's stream is `KnownGround` (`HN_known`).
- NetDestroy, untold deletes nothing (§5 Untold): the loop it prevents needs a node that took T back without the deleted bodies; a node that forgot S syncs it no more here, so that node does not exist in the model.
