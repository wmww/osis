# Networking rework model (TLA+)
> Summary: TLC models of the networking rework before it is built (issues/net-shared-set.md, issues/net-reconnect.md). `NetStream.tla`: node-wide log, cursors, Pull, joins, Lost, restarts, record loss, restored or copied stores, deletion expiry, `Synced`. `NetShared.tla`: beacon filters, generations, pending set, Hit and tag, ByRole, Lost, rotations and removals on one side. Each rule of the design is a flag; turning it off finds a counterexample.

Files: `NetStream.tla`, `MCStream.tla`, `NetShared.tla`, `MCShared.tla`, cfgs `S_*` / `SN_*` (stream) and `T_*` / `TN_*` (shared); `*N_*` are rule removals, which must fail. `ASSUMPTIONS.md`: what is abstracted.

## Run
`tools/heavy env TLC_WORKERS=12 ../run.sh netstream` and `netshared` from this directory; `S_members.cfg` (22M states, about 3.5 min at 12 workers) and `T_rot.cfg` by name. Keep state directories out of the repo (`-metadir`).

## Properties
- `NoWriteLost`: no node drops a write nobody deleted.
- `CaughtUpHolds`: a source judged caught up (L open, last pull reached its end, nothing announced since) holds nothing of L this node lacks, unless deleted somewhere.
- `ServedRight`: nothing is served for a sync ID the peer has lost the right to.
- `ReconnectCost`: a from-the-start reply happens only if the record is gone, the store's history is another's, or a deletion really dropped above the cursor; otherwise a reconnect sends what changed.
- `Settles`: the connection settles (liveness).
- `RuleHolds`: when quiet, L is open on both sides or neither, exactly when each side's rule holds on what it holds now.
- `EpochReached`: a holder served at a rotation reaches the new epoch (issues/net-shared-set.md, the event that ends sharing is still sent).

## Results
TLC 2.19, 12 workers. Positive cfgs pass; each `*N_*` fails with the listed property.

| cfg | scenario | result | states |
|---|---|---|---|
| S_loss | restart, record loss, delete, expiry, drop | pass | 2,309,755 |
| S_restore | b restored from a backup taken at any instant | pass | 3,742,937 |
| S_copies | b and its restored copy both live, one pair key | pass | 3,048,345 |
| S_join | a second sync ID joins a running stream, paged | pass | 998,541 |
| S_members | role gained and lost mid-connection, rejoin from lag | pass | 21,982,718 |
| S_oneway | only the far side can dial | pass, `Settles` | 8,395 |
| S_live | settles after restart and drop | pass, `Settles` | 17,789 |
| T_cred | two nodes, one credential, no role knowledge | pass | 134 |
| T_gain | a credential gained while connected | pass | 36,153 |
| T_rot | rotation at a holder (by name: 39M states, 3 min at 12 workers) | pass | 39,178,520 |
| T_remove | role removed, learned on one side | pass | 280,003 |
| T_recloss | record lost on one side | pass | 6,538 |
| T_copies | filter generations with two live copies | pass | 4,724 |
| T_hostile | peer answers any Hit, claims every credential | pass | 462 |
| T_until, T_live | rotation event served before Lost; liveness | pass | 274,445; 3,067 |

Rule removals: `SN_infer_lit`, `SN_infer_knew` NoWriteLost; `SN_horizon` ReconnectCost; `SN_inc`, `SN_copies`, `SN_sreconcile`, `SN_joindur`, `SN_joinans`, `SN_lostolder`, `SN_cursor`, `SN_rearm` CaughtUpHolds; `SN_gate` ServedRight; `SN_bothpull` Settles; `TN_pending`, `TN_ack`, `TN_arrival`, `TN_tag`, `TN_resend`, `TN_genbase`, `TN_byrole`, `TN_reconcile`, `TN_retest` RuleHolds; `TN_until` EpochReached.

Two rules are redundant given the S digest (`SReconcile`): `ResendLost` and `GenBase` fail only with it off (`TN_resend`, `TN_genbase` turn it off to show this).
