# Networking rework model (TLA+)
> Summary: TLC models of the sync design (spec/sync.md and spec/sync-*.md). `NetStream.tla`: node-wide log, cursors, Pull, joins, Lost, restarts, record loss, restored or copied stores, deletion expiry, `Synced`. `NetShared.tla`: beacon filters, generations, pending set, Hit and tag, Lost, the digest, rotations and removals. `NetOpen.tla`: the one open rule (spec/sync-opens.md §4): each side opens S only on its own proof judged on what it holds now, a credential of its head (a sync proof, or a head claim by an open signature bound to the signer's side) whole, an older step's sync proof served up to that step's end; a head move (a removal rotates) ends each whole open by an older credential; readers and stores, a holder granted later opening by its claim before it holds a seed. `NetHold.tla`: hold, log and delete per sync ID (spec/sync-judgement.md §2-§4, spec/sync-compaction.md §1). `NetKeep.tla`: a node keeping S unread following its own grant, dropping its copy at a head past its keys (spec/sync-judgement.md §6). Each rule of the design is a flag; turning it off finds a counterexample.

Files: `NetStream.tla`, `MCStream.tla`, `NetShared.tla`, `MCShared.tla`, `NetOpen.tla`, `MCOpen.tla`, `NetHold.tla`, `MCHold.tla`, `NetKeep.tla`, `MCKeep.tla`; cfgs `S_*` / `SN_*` (stream), `T_*` / `TN_*` (shared), `O_*` / `ON_*` (opens), `H_*` / `HN_*` / `HL_*` (hold), `K_*` / `KN_*` (keep); `*N_*` are rule removals, which must fail; `HL_*` shows a limit the spec states. Each cfg's first line says what it checks and why a failing one fails. `ASSUMPTIONS.md`: what is abstracted.

## Run
`tools/heavy env TMPDIR=<dir on disk> TLC_WORKERS=12 ../run.sh netstream`, `netshared`, `netopen` from this directory (`run.sh` puts TLC state in `TMPDIR`: never tmpfs). `netopen` runs in about 7 minutes at 12 workers (load 23). `O_rkjunk.cfg`, `O_pub3.cfg` (three connections, safety only), `S_members.cfg`, `T_rot.cfg`, `T_untildrop.cfg`, `T_rotdrop.cfg`, `T_followremdrop.cfg` by name (under a few minutes each at 12 workers). `nethold` (95 s) and `netkeep` (10 s) at one worker need no lock; `H_hostile2.cfg` by name (64 s at 12 workers), `S_pres.cfg` by name (89 s at 12 workers), `S_echo.cfg` (62 s), `S_echowait.cfg` (27 s) and `S_echorestore.cfg` (about 600 s at load 30, one hold of its own) by name at 12 workers.

## Principle
A record says only what need not be sent again: a connection first proves the two records agree (a digest of S, first each way), then sends what changed; nothing about data is inferred from absence: an entry leaves a node by a log event or a right holder's delete, a member leaves S by a `Lost` or a digest difference.

## Properties
- `NoWriteLost`: no node drops a write nobody deleted.
- `CaughtUpHolds`: a source judged caught up (L open, last pull reached its end, nothing announced since) holds nothing of L this node lacks, unless deleted somewhere.
- `CaughtUpServed` (spec/sync-status.md §1, both halves): caught up also needs the peer to have pulled this node's stream to its end and Applied it, nothing left to push; then the peer holds what this node holds, unless deleted somewhere.
- `PresenceSound` (`TrackPres`; spec/sync-judgement.md §3 `known`): caught up with a source, nothing this node holds as present there is missing there.
- `PresenceComplete` (`TrackPres`, no copied store): caught up both ways, an entry both hold this node counts its peer holding. `Echo` "applied" is the built design (spec/sync-streams.md §4 Reports): a server counts each Added it sent that its requester reported applied and told no refusal of (the requester tells, before its Applied, what it does not hold), and lists no Added its requester counts it holding, the count kept with the connection, outside a listing from the start; the Applied carries the requester's log end (the anchor), which the server's next Pulls to it name until a reply checked it, a server whose history lacks it answering from the start, and the held anchor is replaced only once checked (a newer one waits, with the counts it carries, and both end with the connection: a count stands only on an anchor checked on the connection that counts it); a listing from the start spends the held anchor where none waits. `Echo` "stream" (a requester streams back what it took) is a simpler stand-in the cfgs about cursors, joins and the shared set run, their rules not turning on how presence is learned.
- `DeletionsArrive`: a deletion the source's log still holds reaches a node caught up with it.
- `ServedRight`: nothing is served for a sync ID the peer has lost the right to.
- `ReconnectCost`: a from-the-start reply happens only if the record is gone or the store is a restored or copied one; a restart and a long absence never force one.
- `Settles`: the connection settles (liveness).
- `RuleHolds`: when quiet, L is open on both sides or neither, exactly when each side's rule holds on what it holds now.
- `UntilEnds`: when quiet, no open rests on a proof a rotation made stale: the requester's report of passing `until` always arrives.
- `EpochReached`: a holder with L open on both sides at a rotation, no record lost, reaches the new epoch.
- NetOpen: `Private` (Adv holding no value of S: no Lost names S to it), `Safe` (no honest node serves Adv a step Adv was not a holder at: a whole open serves the node's head, an ended one up to its `until`; so a removed holder is served nothing past its removal's step once the node knows the removal, and a node holding only S's public values nothing; Adv replays any token it was sent; every `O_*` cfg), `Live` (two honest holders on one connection, every event known to both, end up open whole both ways, whichever dialed; weak fairness of honest steps per connection; the 2-connection cfgs), `ClassRight` (an open between honest nodes records the class its peer declared, whichever side's Hit opened it and on whichever credential; every `O_*` cfg).
- NetHold (readers r1, r2 writing S; K keeping S unread; optionally H, a hostile writer deleting at K; b a write by r2, c r1's snapshot covering it, x r2's role commit making c invalid; r2 keeps b under c as local data, its entries out of r2's log): `Bounded` (no loop: per reader and body at most one logging again per change of ground, K's head or a fall of c there), `Carried` (no honest delete takes b while K, not full, holds no c), `NoLoss` (a needed body is held by an honest reader or K; c once x fell only if K ever held it), `QuietAlike` (no H, quiet: every reader reads b's write, holds c when needed and b when kept, and K holds every needed body), `Settles` (liveness: quiet is reached and stays), `NoCap` (the run's encryption bound was not what stopped a loop).
- NetKeep (the granter may re-grant K once after removing it; the account may unlist and list again): `OnlyBoxedContent` (K holds content only of steps it was boxed at), `RemovedHoldsNothing` and `RemovedClosed` (removed, its head past the removal, K holds nothing and opens S nowhere), `FewStops` (K drops its copy a bounded number of times: no loop), `Refetches` (once quiet, a K boxed at the current epoch and listed holds the head's content: a late box or a re-grant re-fetches).

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
| S_echo | `Echo` "applied": record loss, delete, expiry with trimmed replies, drop; `PresenceSound`, `PresenceComplete` (by hand: 62 s at 12 workers, past the module budget at one) | pass | 910,633 |
| S_echorestore | `Echo` "applied" in `S_pres`'s world: b restored from a backup taken at any instant (by hand: 506-597 s at 12 workers at load 30, a hold of its own) | pass | 8,503,108 |
| SN_echotold, SN_echocount, SN_echodurable | an applied send counted though not held and not told; the filter with no send counted; the count kept with the record across connections | fail `PresenceSound`, `PresenceComplete`, `PresenceComplete` | |
| SN_echoanchor, SN_echocheck | no anchor: a restored b counted holding what it took after the backup (a's cursor still names a position there); the held anchor replaced by the restored store's first Applied, before a reply checked it | fail `PresenceSound` | |
| S_echowait | `Echo` "applied", two takes from a (`AuA`): b restored from a backup at any instant, one drop; `PresenceSound`, `PresenceComplete` (by hand: 27 s at 12 workers) | pass | 605,065 |
| SN_echowait | `Echo` "carried": a waiting anchor's counts taken at once, the anchor kept across connections: b takes e1 (a0) and on the next connection e2 (a1 waits), b is restored from between, the next connection checks a0 and promotes a1, and a counts b holding e2 | fail `PresenceSound` | |
| S_reportwin | `Echo` "applied": b lists a's e1, e2 in two pages (`PageK` 1), both pull; every applied page reports, a listing's too (one reply in flight: the server's `REPORT_WINDOW` never binds here, the model keeping every message an Applied names) | pass | 1,684 |
| SN_reportwin | `Echo` "window": a listing reports at its last page alone and a counts that page's sends only, its window passed, while b counts both pages': b streams e1 back never, and a never counts b holding it | fail `PresenceComplete` | 1,544 |
| S_pres | presence: deletes, expiry with trimmed replies, b restored from a backup (by name; `DeletionsArrive` off: a deletion the restored copy still logs lies below a cursor read past its expiry at b, the stated limit) | pass (89 s at 12 workers) | 4,597,182 |
| T_cred | two nodes, one credential | pass | 2,944 |
| T_gain | a credential gained while connected | pass | 11,414 |
| T_remove | role removed (the removed side applies no later rotation), drop | pass | 8,832 |
| T_recloss | record lost on one side | pass | 6,031 |
| T_copies | filter generations with two live copies | pass | 88,277 |
| T_hostile | peer answers any Hit, claims every credential | pass | 683 |
| T_until | rotation event served before Lost | pass | 14,039 |
| T_follow | rotation with `follow`: only a Push marked `report` is answered | pass | 8,844 |
| T_followdrop | ... and a drop after the rotation | pass | 88,510 |
| T_followrem | ... with a removal | pass | 47,081 |
| T_live | settles, with a rotation | pass, `Settles` | 25,790 |
| T_untildrop | rotation then a drop (by name, bounded) | pass | 92,356 |
| T_rot | rotation and removal (by name, bounded, no drop) | pass | 53,742 |
| T_rotdrop | rotation, then a drop, no removal (by name, bounded) | pass | 171,994 |
| T_followremdrop | follow, rotation, removal, a drop (by name, bounded) | pass | 506,471 |
| S_members | role gained and lost mid-connection, rejoin from lag (by name) | pass | 19,360,038 |
| O_rk | a reader, a store granted later (opening by its claim, then taking its entries); Adv a holder, removed (a rotation), then a rotation; 2 connections | pass, `Live` (276 s at 12 workers, load 23) | 178,348 |
| O_kk | two stores; Adv a holder, removed, then a rotation; 2 connections | pass, `Live` (77 s) | 76,738 |
| O_pub | a reader, a store, a rotation; Adv never a holder, holding S's public values; 2 connections | pass, `Live` | 2,679 |
| O_none | as O_pub, Adv holds no value of S and shows junk filter entries both Hit | pass, `Live`, `Private` | 18,263 |
| O_rkjunk | as O_rk, Adv's junk entries Hit too (by name) | pass, `Live` (650 s at 12 workers, load 23) | 383,068 |
| O_pub3 | as O_pub, 3 connections (by name, safety) | pass (15 s at 12 workers) | 98,351 |
| H_quiet | two readers, K, x; the spec's rules | pass | 1,661 |
| H_head | ... a head move at K | pass | 9,510 |
| H_meet | ... readers also pull each other | pass | 3,659 |
| H_full1 | K full with room for one, tombstones expiring | pass | 1,693 |
| H_full2 | room for two, with x | pass | 1,501 |
| H_expire | tombstones expire | pass | 44,009 |
| H_hostile | H deletes once | pass | 210,327 |
| H_hostile2 | H deletes twice (by name, 64 s at 12 workers) | pass | 5,971,488 |
| H_live | settles: head move, room for two, expiry | pass, `Settles` | 69,439 |
| HN_standhead, HN_snap | stand ground without the head; no unheld-snapshot clause | pass (not needed by any property here) | 7,002, 1,786 |
| H_keep | b kept (must-hold whatever covers it) | pass | 124 |
| H_xfall | x falls: c fetched back where dropped as invalid | pass | 22,447 |
| H_restart | readers restart, the stand durable, a head move | pass | 19,020 |
| K_all | rotations, a removal, a re-grant, unlisting and listing again, boxes and Registers in any order | pass | 3,425 |
| K_nohead | ... granted before any step is registered (no head: shows every secret it holds), first box late | pass | 7,603 |
| K_fake | ... a hostile box of a self-made epoch: hides no key, keeps no removed copy | pass | 6,850 |

Rule removals: `SN_infer_lit`, `SN_infer_knew` NoWriteLost; `SN_history` ReconnectCost; `SN_listdels` DeletionsArrive; `SN_inc`, `SN_copies`, `SN_sreconcile`, `SN_joindur`, `SN_joinans`, `SN_lostolder`, `SN_cursor`, `SN_rearm` CaughtUpHolds; `SN_gate` ServedRight; `SN_bothpull` Settles; `SN_servehalf` (caught up from the pulling half alone), `SN_applied` (a reply served to the end counted before the peer's Applied) CaughtUpServed; `SN_trim` (no trimmed reply: a cursor below an expired deletion reads on, presence keeps the entry) PresenceSound; `TN_pending`, `TN_ack`, `TN_untilack`, `TN_arrival`, `TN_tag`, `TN_genbase`, `TN_reconcile`, `TN_retest`, `TN_decline`, `TN_offergate`, `TN_reptested` RuleHolds; `TN_until` EpochReached; `TN_report`, `TN_cursorrep` UntilEnds; `ON_side` (no side byte: a reader behind Hits its own claim at the next step toward Adv; once it learns that step, Adv reflects the signature as its Hit), `ON_answer` (a tester opens without a valid answer: the store granted later Hits the claim Adv shows), `ON_old` (an older step's proof opens whole: the removed Adv is served past its removal), `ON_endhead` (a head move ends nothing: an open toward Adv outlives its removal's rotation), `ON_claimold` (a claim bound to an older epoch counts), `ON_proofpub` (the proof from the public sync key: Adv computes the new step's), `ON_deposit` (a Hit on the head's deposit key opens), `ON_dialer` (the dialer opens toward the key it dialed) Safe; `ON_noclaim` (no claims: the store granted later holds no seed and never opens) Live; `ON_losttag` (a Lost on an acceptance without a valid answer: a tester Hits Adv's junk entry and the Lost names S to a peer holding no value of S) Private; `ON_class` (the class from the credential: the reader classes the store, opened by its claim, a reader) ClassRight.


Rule removals: `HN_stand` Bounded (log-liar loop); `HN_standfall`, `HN_fallany` (only a fall of a held part ends the stand: a node that got c already invalid keeps standing), `HN_fresh`, `HN_rolefirst`, `HN_delview` (a delete does not wait for a role commit K's stream shows), `HN_invalid` (a snapshot judged invalid still counts against established uncovered), `HN_full` QuietAlike; `HN_ownlog` (the author keeps its covered body in its log: K pulls it back at each tombstone expiry and it is deleted again) Settles; `HN_known` Carried; `HN_readers` NoLoss; `HN_mustdrop` (a kept body covered and dropped: K lacks it) QuietAlike; `HN_invaliddel` (c dropped as invalid deleted at K: once x falls c is gone everywhere) NoLoss; `HN_fixpoint` (r1 takes x and, before judging c invalid, deletes b's logged-again encryption at K under c; r2's stand holds, K lacks b) QuietAlike; `HN_durable` (a restart loses the stand: b logged again past a delete that stands) Bounded; `KN_keep` (keeps its copy at a head past its keys) RemovedHoldsNothing; `KN_open` (past its keys, shows every held secret) RemovedClosed; `KN_shownone` (past its keys, shows nothing: a re-grant after a further rotation is never registered onward) Refetches; `KN_take` (takes at a head past its keys: content stamped for a step after its removal while a re-grant's path climbs) OnlyBoxedContent; `KN_droppath` (a stop shreds the path too: with no head K shows its old secrets, the granter registers the path again, K stops again) FewStops.

Limit (`HL_capjunk`, spec/sync-judgement.md §3 Deletes): an invalid body is never deleted at peers (spec/permissions.md §6), so at a full store it holds room a needed body is refused for, until expiry or the caps give way; QuietAlike fails.

## Findings
- `SN_echoanchor`: a send counted at its Applied with no anchor stands on no position of the requester's log, so a restore of the requester is not seen: a writes e1; b takes it and reports it applied, and a counts b holding e1; b is restored from a backup taken before, keeping a's record; a's stream cursor at b is below where b took e1 (b's stream skipped it), so it names a position of the restored history and no listing from the start follows: a counts it holding e1, which it lacks. The anchor ties the count to b's history as the echo's cursor did. Rejected: the count waiting until the requester's stream sent a cursor covering its event of the entry (an empty push where the filter skipped): with both replies paged neither side follows the other, a deadlock.
- `SN_pres` (spec/sync-streams.md §4 Applying, open): the spec lets only a listing from the start marked `trimmed` replace what a requester holds as present at the source; any other listing from the start (a cursor naming no position at a restored or copied store, a join from the start) leaves stale presence. Trace (`SN_pres`, 13 states): a and b connected; a backup c of b is taken; b writes e2; a pulls it (e2 present at b); b is restored from c, keeping a's record; a's cursor names no position in c's history, so c answers from the start, not trimmed; the listing ends without e2 and a still counts e2 present there (it would count e2 held elsewhere while that store lacks it). Proposed fix (the coordinator's decision): "A listing never treats an absent entry as deleted, except that a listing from the start (trimmed, a cursor naming no position, or a join from the start), once complete, replaces what the requester holds as present there for its members." `S_pres` passes with it, `SN_trim` shows the trimmed half is needed too.
- Presence completeness at a restored store (stated limit, not a fix): an entry b deleted after a backup has its add event compacted away below a cursor a later reads at b; restored from that backup, the store holds the entry again under the same incarnation, and a's cursor, honoured there, never shows it. Only deleted entries come back so (compaction moves an event only on a deletion), so presence errs toward absent: data-safe, but a right holder never deletes the resurrected entry at a store keeping S unread until something lists it again. `PresenceSound` checks the safe direction only.

## Rules these models do not reach
- NetOpen, three connections with a removed Adv (a reader and a store, or two stores): past reach (two stores passed 3.2 million states unfinished in 10 minutes at 12 workers); `O_pub3` is the three-connection run.
- NetOpen, filter width and the additions count (spec/sync-opens.md §5): a filter is a set of values, not bits. A junk entry matching what a tester tests is modelled (`AdvJunk`) as always possible; width enforcement bounds how often, a rate the model does not express.
- NetStream, the rest of a partly answered Fetch asked before what came is applied (spec/sync-streams.md §4 Bodies): an event carries its entry; Fetch, bodies and fill order are out.
- NetOpen, when a side tests (spec/sync-opens.md §5 Testing: its own changes and re-marks): any Hit on a value shown is enabled at any time, so `Live` holds whichever side tests; that a store with no head shows its held secrets' proofs and its own test opens S is tested in core/sync (`opens::a_store_granted_later_opens_with_no_head_spec_sync_opens_4`).
- NetHold, first logging verbatim (spec/sync-judgement.md §3 Own store): with one sync ID, logging a held blob verbatim or as a fresh encryption differs only in cost; the author's entries returning to its log keep their blob IDs, and logging again is fresh (`HN_fresh`). Judgement per (S, commit, source) from that source's stream is `KnownGround` (`HN_known`).
