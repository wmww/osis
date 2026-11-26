# A reader lowered to sync before it ran never reads a public thing
> Summary: a node whose account is granted read on a public thing and lowered to sync before the node first runs keeps it unread for good: its store's `lowered_at` is the head, which lists the public entry, so `unread::judge` refuses that head's public box, and it holds no public grant (it never took the thing's role commits as a reader). The model reads it by the public.
> Priority: normal
> Tags: sync, engine

Script (fails at `holds_on(0, 3, 4, ..)`, seed 1 of the full-size differential): `New(2), Give(2, 0, Holder::Public, Reads), Give(2, 0, Holder::Node(1), Reads), Strong(1, None, 0), Lower(2, 0, Holder::Node(1), Syncs)`. At quiet node 1 keeps thing 0 unread, `public_reads` false, its store's `lowered_at` equal to its head (checked), the head listing the public entry.

spec/sync-opens.md §4 (keeping S unread): the head a node was lowered to sync at gives nothing "until a Register moves it", since it read there what ended the public's read. Here what it read there ended its own read, not the public's; the lowering rotates no sync epoch and nothing moves the head, so the node never takes the box. Without the prior read (only ever sync) it reads by the public at once.

The script passes on branch `spar-public-timing` (an entry box judged by its party's departures, Following by the public entry), at `holds_on(0, 3, 4, ..)` and as full-size seed 1; why is unconfirmed: confirm the cause, then delete this issue.

Unexamined: whether the node, having read at that head, should hold the public's grant already (the issue's first guess: `Core::sync_alone_on` false once a held edge write gave read, so its edge piece came as certificate copies and the public's grant commit was never held). A fix probably makes the lowered-head exclusion name the public's own ending (the head bears an epoch the public's removal superseded) rather than any lowering.
