# A sibling's concurrent removal and rotation never open through sync
> Summary: Two nodes of one account each remove a node while apart; through sync, neither learns the other's devices-actor epoch, so the other's account rotation stays an unopened entry (NotOpen) for good; handed over directly, both apply.
> Priority: normal
> Tags: sync, engine, security

Reproduce (core/sync/tests/it/duties.rs shape): four siblings of one account, nodes 2 and 3 off, nodes 0 and 1 partitioned; node 0 removes node 2, node 1 removes node 3 (each `demote` on D: the removal with D's rotation, then P's rotation); heal, run.
- At each of nodes 0 and 1: the other's removal is applied (`header` present, all three parts held, `blob_parts` {0,1,2}, not a copy), yet `epochs(D).read` holds only the node's own n=2 epoch: the other's D epoch, boxed to it by that removal, is never learned.
- So the other's P rotation, wrapped under that D epoch, stays `Opened::NotOpen` in the store (opening it by hand with `open_entry` after the run: still NotOpen), across a restart too.
- The same commits handed over by `ingest_with_lists` instead (before or after the run) apply, and the node then holds both D epochs (two current) and owes the merge rotation.

So something on the sync path (open_entry: `open_commit`, the sections' openings, `note_unwrapped`, then `ingest` of the plaintext) leaves the removal's `secrets.0` boxes unopened or untaken where a plain ingest takes them. Until fixed, a sibling's concurrent removal is never covered at the other node: its account's fork is never merged (`signing_due` sees one head).

The duties test hands the commits over to test the pass-end rotation alone; once fixed, it should let sync carry them.
