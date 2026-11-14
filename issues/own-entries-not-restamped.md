# A writer's own entries keep their stamp across a head move
> Summary: at a writer of S, `Ground::stands` takes an own entry as its log whatever head it was stamped under, so after a head move (a rotation, a new step) nothing restamps it; stores keeping S unread then refuse it (code 9) and take it only as readers' fresh deposits.
> Priority: normal
> Tags: sync, read

spec/sync-judgement.md §3 Own store: a node logs what S must hold "stamped when it writes S"; spec/sync-streams.md §4 Refused: once the head moved, "a new stamp goes as its own event". `Live::stands` restamps a peer's entry in place when its stamp does not verify under the store's head (`stamp_vouches`), but returns true for `e.own` first, so an own entry stamped under an older head stands for ever.

Cost: after every head move a store source that registered the new head refuses each older own entry (code 9). Readers that are no writers then deposit a fresh encryption of each must-hold body (`Live::deposit`: the entry is not stamped under the source's head), those deposits are listed in their streams and every other reader pulls them as duplicates charged to the depositor (spec/sync-ids.md §5): one head move turns into a fresh blob per body per non-writer reader, and fills honest readers' budgets at each other.

Fix shape: drop the `e.own` shortcut where this node holds S's head write key (an own entry stands only stamped under the head, else restamped through `log_own`'s verbatim path like a peer's), and check (a) that a head move re-judges each body at a writer once (`stamp_vouches` reads the head row inside the body's effects), at n and 10n bodies, and (b) that `own_entry`'s key (`signers(s).stamp`) and the store's path head agree once the step is issued, else each re-judge restamps again. Test: a writer's own entry, head moved, is logged again stamped under the new head; a store that registered the new head takes it.
