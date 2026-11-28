# `contact show` and `link make` time out on a node no other node holds the thing at
> Summary: The CLI waits after `contact show`, `link make`/`chat link`, `grant` and `chat add` until what it wrote is held where it goes (`wait_synced`); for a public profile or a link key any peer may hold the sync ID, so on a node with no connected peer the wait never ends and the command exits 6 ("done here, not yet held where it goes") after its timeout, every time, though the card or link works.
> Priority: low
> Tags: cli, sync

Seen in the dogfood smoke pass on a fresh lone store (`contact show`: 10 s with `--timeout 10s`, exit 6, again on a second run that wrote nothing). The wait follows spec/sync-set.md §3 (To be waited for: S kept unread, or public, any peer). Question: what "delivered" should mean for a thing whose holders are anyone (none to wait for, or the first peer), and whether showing a card should wait at all: it names this node, which serves it.
