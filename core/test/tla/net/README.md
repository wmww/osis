# Networking rework model (TLA+)
> Summary: TLC models of the networking rework before it is built (issues/net-shared-set.md, issues/net-reconnect.md). `NetStream.tla`: node-wide log, cursors, Pull, joins, Lost, restarts, record loss, restored or copied stores, deletion expiry, `Synced`. `NetShared.tla`: beacon filters, generations, pending set, Hit and tag, ByRole, Lost, the digest, rotations and removals on one side. `NetBlind.tla`: a peer that cannot read. Each rule of the design is a flag; turning it off finds a counterexample.

Files: `NetStream.tla`, `MCStream.tla`, `NetShared.tla`, `MCShared.tla`, `NetBlind.tla`, `MCBlind.tla`; cfgs `S_*` / `SN_*` (stream), `T_*` / `TN_*` (shared), `B_*` / `BN_*` (cannot read); `*N_*` are rule removals, which must fail. `ASSUMPTIONS.md`: what is abstracted.

## Run
`tools/heavy env TMPDIR=<dir on disk> TLC_WORKERS=12 ../run.sh netstream`, `netshared`, `netblind` from this directory (`run.sh` puts TLC state in `TMPDIR`: never tmpfs). `S_members.cfg`, `T_rot.cfg`, `T_untildrop.cfg`, `T_rotdrop.cfg` by name (minutes each, `T_untildrop` 75M states, `T_rotdrop` 378M, half an hour at 12 workers).

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
- `EpochReached`: a holder with L open on both sides at a rotation, no record lost, reaches the new epoch.
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
| T_cred | two nodes, one credential, no role knowledge | pass | 122,153 |
| T_gain | a credential gained while connected | pass | 6,578,636 |
| T_remove | role removed, learned on one side, drop | pass | 18,407,326 |
| T_recloss | record lost on one side | pass | 2,794,798 |
| T_copies | filter generations with two live copies | pass | 4,524,894 |
| T_hostile | peer answers any Hit, claims every credential | pass | 1,890 |
| T_until | rotation event served before Lost | pass | 2,026,738 |
| T_live | settles, with a rotation | pass, `Settles` | 8,919,985 |
| T_untildrop | rotation then a drop (by name, bounded) | pass | 75,003,618 |
| T_rot | rotation and removal (by name, bounded, no drop) | pass | 53,364,578 |
| T_rotdrop | rotation, then a drop, ByRole on, no removal (by name, bounded) | pass | 378,001,162 |
| S_members | role gained and lost mid-connection, rejoin from lag (by name) | pass | 19,360,038 |
| B_all | a peer that cannot read: drop, backup restore, record loss | pass | 4,185 |
| B_live | settles | pass, `Settles` | 486 |

Rule removals: `SN_infer_lit`, `SN_infer_knew` NoWriteLost; `SN_history` ReconnectCost; `SN_listdels` DeletionsArrive; `SN_inc`, `SN_copies`, `SN_sreconcile`, `SN_joindur`, `SN_joinans`, `SN_lostolder`, `SN_cursor`, `SN_rearm` CaughtUpHolds; `SN_gate` ServedRight; `SN_bothpull` Settles; `TN_pending`, `TN_ack`, `TN_untilack`, `TN_arrival`, `TN_tag`, `TN_genbase`, `TN_byrole`, `TN_reconcile`, `TN_retest`, `TN_decline` RuleHolds; `TN_until` EpochReached; `BN_upack`, `BN_whole` Placed; `BN_cover` Carried; `BN_known` DeletesReach.

