# Inbox label hints make devices dial servers a stranger names
> Summary: every opened inbox blob adds its payload's (label, servers) as hints before anything is checked; node-sync then dials those servers and keeps them wanted until the named thing's `/label` names the label, which for a made-up thing is never. A stranger with the inbox deposit seed makes all of a person's devices connect to its servers indefinitely (IP and online-time leak, unbounded connection fan-out).
> Tags: security, node, sync

Severity: medium (privacy: device IPs and presence to an attacker; DoS: one inbox blob can name many things and servers).

Where: core/node/src/sync/inbound.rs:432-437 (`open_one`: `add_hint` for every payload thing whose label the node does not know, commit unchecked; only `peer://` filtered); core/node/src/sync/mod.rs:1080 (`wanted_servers` dials every hint server) and :1289 (`wanted_labels` opens them); hints are removed only in `run_dirty` when `labels_of(thing)` names the label, and on forget. No cap on hint count, no expiry with the inbox blob. `MAX_HINT_COMMITS` bounds delete-key hints, not these.

Scenario: as in issues/inbox-copy-any-commit.md, a stranger deposits inbox blobs whose payload lists thousands of random tids with labels on servers it runs. Every device of the victim dials them, opens labels there (revealing its transport address and timing), and keeps retrying for good.

Fix direction: add hints only from a blob whose commit carries a box to the inbox actor that opens (a real grant; the joiner case in notes/sync.md Inbox life still works while the granter's chain is pending), only for things that commit touches, capped per actor, and drop them when the inbox blob expires or its commit is judged invalid.
