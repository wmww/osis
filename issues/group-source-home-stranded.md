# Moving a group home can strand its label
> Summary: After `group_source(G, Remote)` then `Local`, or `receipts_only` on then off, G's label can fail to open on the live host connection (every key refused, code 1), so the move home fails `Unsynced` again and again; a new host connection clears it. Seen when a thing of G was just shared into a second group.
> Tags: node-sync, osis, tests

Reproduced on branch `group-sources` (in-process, one host, `sources` test world): `p.share_into(t, h, Write, ..)`, wait synced, `attach_p`, `to_remote`, `group_source(g, Local)`: first try `Unsynced` in 7 of 12 runs, and still so after 75 s of retries in the run that waited that long; plain worlds without the share: 12 of 12 fine. The same with `sync_policy(g, receipts_only: true)`, then `false`, no routes at all: 5 of 8 runs stranded after 1 s; dropping the host connection recovered all 5 in 3 s. Dropping and healing the host without the toggle: 0 of 8.

What the user sees: the call says `Unsynced` while `status` shows G `Synced` (the node's state, since the route stands). Nothing is lost: the route stays, reads and writes keep going to the node, the node's clients read G as unknown, and syncing here has resumed behind that.

Where: `open.rs` `refused` -> `try_next` -> `Phase::Failed` on a label reopened on the same connection; "every open proof holds at the head only" (`serving.rs` `open`), so the keys tried are not the head's on that connection. Why the head differs and why a new connection helps is not worked out. Whether main shows the toggle form is not checked (`set_receipts_only` is on main; this branch adds one line to it).

The move's retry loop cannot fix it: it only reads the label's state. `group_source_differential_against_a_model` accepts `Unsynced` from a move and shares nothing, so it does not see this.
