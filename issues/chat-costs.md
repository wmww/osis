# Chat join, message and removal cost far over the notes/chat.md estimates
> Summary: Measured through the example chat (examples/chat `costs_join_message_removal`, tier 2, upstream bytes at the server): a join sends ~220 KB, a message ~2.5 KB, removing one of four participants ~350 KB from the moderator plus ~160 KB from the others. notes/chat.md estimates about 10-20 KB, 350 B plus content, and two ~1.2 KB boxes per remaining member. Also: a second link plus a link-joiner removal never settles.
> Tags: sync, node, api, tests

Numbers (chat of 4 through one multi-use link, debug build, osis-sim `World` tally by message kind):
- Join (redeem, persona, edge, subgroup): 14 `Upload` frames, 217 KB; 2 `Deposit`, 5 KB.
- Message (text, sent time, placement on the persona's `/group`): one `Upload` of 2.5 KB.
- Removal of a link joiner (`demote(K, person)`, `revoke_link(K)` with pre-sync): 27 `Upload` frames, 338 KB, 11 `Delete`, 4 `Register`; the other members send 160 KB meanwhile.
- Grants generally: a read grant makes the grantee re-deposit its certificates quadratically (issues/sync-deposit-resend.md), part of the join figure.

To find out (node-sync, labeling): what the join and removal uploads carry (whole-label re-uploads after a rotation? certificate copies per label? projections per reader actor?), and whether the message's 2.5 KB is header, tokens, padding or the second aspect's projection. The test prints the per-kind tallies; `World::start_tally` / `tally` give them for any scenario.

Hang: with a second link made after the joins (`invite` again, a late joiner through it), removing an earlier joiner never settles: after `revoke_link`, the world's message pump runs for minutes without quiescing (CPU-bound, debug build; repro: in the costs test, give the late joiner a fresh `invite(&alice, c, false)` link, `OSIS_CHAT_N=3`). Not reduced further; likely a sync storm after K's rotation (compare issues/sync-compaction-ping-pong.md, issues/sync-duplicate-reupload.md).
