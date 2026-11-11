# Serving refusals: admitting by sync ID cannot take links
> Summary: A serving node that does not read a group, admitting by sync ID (`--admitted ID`), refuses a link's new K sync ID; a node that reads the group takes links.
> Priority: low
> Tags: cli, node-sync, host, security

A serving node that reads the sharer's groups (one of the account's nodes) covers links: it reads K too and stores what it reads (issues/net-one-peer.md step 4). A node admitting by sync ID (`serving set --admitted ID`, one that never reads the group) cannot: each `link make` makes a new K label (K's home label, spec/sync.md §2) it was never told about, and grants deposit into recipients' inboxes (their own peers' business, not this node's). No small rule fits: the serving node cannot tie K to G without reading G. Options: the CLI prints K's sync ID on `link make` (as `serving ids G` lists a group's) for the serving node's admin to add, or `serving set --admitted` takes a key actor's public key and admits labels whose genesis registration that key signs (protocol change).
