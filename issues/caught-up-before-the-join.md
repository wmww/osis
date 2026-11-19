# Caught up before the source's join of a new member
> Summary: A member S that joins a connection after the source's last Pull was answered counts caught up at the server once its own join of S is read, though the source has not yet pulled S (its join Pull is on its way): the follow cursor covers no event of S logged before it (spec/sync-status.md §1).
> Priority: normal
> Tags: sync, status

Reproducer: `streams::repro_a_member_joined_after_the_pull_waits_for_its_join` (ignored): a logs an entry of S, T's stream settles (b followed), S joins at both sides, b's Pull joining S is held back; a says b caught up on S while b lacks the entry. The same on main (caught up per connection had the same window). §1's words allow it: "the source's last Pull was answered with `more` false and it is followed" says nothing of members that joined since; pushes read S only after the follow cursor.

What a user sees: not an early `wait_synced` on its own writes (held elsewhere needs the source's stream to show each, spec/sync-status.md §2), but S heard out at once after a member joins (a grant on an open connection), including the end of a complete pass, while the source still lacks what this node holds of S.

The rule wanted, as a busy cause: S joined after the source's last answered Pull and no reply since read S for the source from where it stands (its join merged, or a reply from the start); that also covers "a join of S left in pages" (`joins_left`). The server's `own` (members reported at a position of their own) marks the same joins but stays until an Applied covers the merge, which a reply with no events never asks: not usable as is. Settle first whether the server can join S after answering the first Pull of a requester that counts S at the stream (no join would ever come, and S's events between the cursor and the reply would never be served): if opens' agreement rules that out, the rule above never waits for good.
