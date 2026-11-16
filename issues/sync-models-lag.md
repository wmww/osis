# Net models lag the rebuilt sync
> Summary: Rules osis-sync implements that no TLA model in core/test/tla/net checks: Behind's refused-for-now retry, the raise to read and its durable mark, code 1 refusals told under a head and the pull anew on a head move, room growth's pull anew and a restart of a full node, who is waited for across an account's key rotation, must-hold only what is loggable and certificate copies, suspect lists, invalid bodies forgotten and given force again, own-key relisten, a registrar holding no secret of a role. Extend the model where a rule could loop or strand; state the rest as not modelled in ASSUMPTIONS.md.
> Priority: low
> Tags: tests, sync

Each line: the rule (spec), the model that should carry it, what it lacks.
- Behind refused for now (4) asked again after a doubling back-off (spec/sync-ids.md §6 Behind; `opens` `Conn::retries`): NetOpen leaves Behind out (ASSUMPTIONS.md, NetOpen). Liveness of a walk past a refused-for-now answer is unchecked.
- Raise from kept unread to read pulls S anew from every source, marked durably (`N/` `ANEW_RAISED`, spec/sync-judgement.md §6 Read and unread move): no model moves a holding between kept unread and read; NetKeep's K never restarts.
- Code 1 refusals kept per (peer, S) under the head told, and a head move pulling S anew from those peers (spec/sync-streams.md §4 Refused): NetHold models only codes 6 and 12; no told head, no pull anew, and no reader-side refusal ending when the entry is offered again, shown present or the refusing node's head moves.
- Room growth pulling S anew through the durable `N/` mark and sending `full` false, judged per refusing cap, and `full` lasting with its connection (spec/sync-streams.md §4 Full): NetHold's K has `full`/`refused` but never restarts and has one cap.
- Who a duty waits for (`opens::awaited`: an account at the key proved with until a rotation past it carries a removal; spec/sync-set.md, who is to be waited for) against who counts (`opens::counted`: trust now): NetDestroy and NetHold have no account key epochs (ASSUMPTIONS.md: account proofs not modelled).
- Must-hold only what this node may log under S (spec/sync-judgement.md §2 Loggable), certificates never dropped as covered, a reader taking an announced entry whose bytes it holds under another sync ID: NetHold leaves certificate copies out.
- Suspect lists and repair, the receiver's first-sync gate (spec/sync-judgement.md, suspect; `inbox/suspect.rs`): no model.
- A body judged invalid leaving every own store untombstoned, forgotten, and a re-grant giving its request force again (spec/sync-judgement.md §2, spec/permissions.md §6): NetHold's `XFall` makes c valid once; forgetting and a second flip are not modelled.
- A listener set's key change closing the sessions taken under the old key (spec/sync-transport.md §5 Key change): NetOpen has no own-key change.
- A registrar none of whose secrets tells a role's step key waiting for its current epochs' rotations (spec/sync-ids.md §6 Steps): NetKeep has no epoch without a step and no history-less holder (notes/history-less-grant.md, Decided 3).
