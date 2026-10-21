# link_race: a race loser's lost chain deposit leaves its promoted `/keys` copy pending
> Summary: In `link_race` (about 1 seed in 100) the losing redeemer deposits its chain certificates under the target's label, one deposit is lost, the loser then drops the label and never re-sends; an admin promoted its person's `/keys` copy, so the winner holds it pending (MissingChain of the person's recovery key) at quiescence.
> Tags: sync, node, tests

Repro: `sim-sweep --only link_race --seeds 100` (seed 41 on main before the chat-cost fix; seed 50 after it; seeds shift with timing).

- Seen: node y (winner) pends the loser's person creation commit; its `/keys` part came from the loser's deposit, promoted by the admin; the deposit holding the recovery key's `/created` and the person's `/created` got no reply, and the loser forgot the label (lost access) before `RESEND_MS`.
- Was masked before the chat-cost fix: every member placed L's revoke under the label with its whole write closure, which happened to carry the loser's person creation. Revokes now go only where an entry of the author is judged invalid (spec/permissions.md §4), which still covers seeds 16 and 27 (the loser's void grant op) but not this ordering.
- Directions: an admin promoting a deposited certificate copy also holds its chain under the label (places what it holds of the copy's author chain), or does not promote a copy whose chain is not under the label; or stale certificates of non-members are outside the required set and verifiers do not pend on them.
