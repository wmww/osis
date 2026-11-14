# A sibling's concurrent removal and rotation never open through sync
> Summary: Two nodes of one account each remove a node while apart; through sync neither ever applies the other's removal (each still holds the other's removed node as an admin of D) and the other's account rotation stays unopened, so each keeps encrypting under a D epoch boxed to the node the other removed: a device removal is silently undone. Handed over directly, both apply.
> Priority: critical
> Tags: sync, engine, security

Severity (probe at the end of this run, after healing and a long advance): at node 0, `role_now(node 3, D)` is still Admin and node 1's removal of node 3 is not a departure there (`departures(D)` lists node 2's only); node 0's current D epoch is its own n=2, made while node 3 was a member and so boxed to it, and node 0 owes nothing (`signing_due` empty). Node 1 likewise keeps node 2. A removed device that ignores its removal keeps reading everything the other sibling writes, and that sibling re-seals and serves it as a device.

Reproduce (core/sync/tests/it/duties.rs shape): four siblings of one account, nodes 2 and 3 off, nodes 0 and 1 partitioned; node 0 removes node 2, node 1 removes node 3 (each `demote` on D: the removal with D's rotation, then P's rotation); heal, run.
- At each of nodes 0 and 1: the other's removal is applied (`header` present, all three parts held, `blob_parts` {0,1,2}, not a copy), yet `epochs(D).read` holds only the node's own n=2 epoch: the other's D epoch, boxed to it by that removal, is never learned.
- So the other's P rotation, wrapped under that D epoch, stays `Opened::NotOpen` in the store (opening it by hand with `open_entry` after the run: still NotOpen), across a restart too.
- The same commits handed over by `ingest_with_lists` instead (before or after the run) apply, and the node then holds both D epochs (two current) and owes the merge rotation.

So something on the sync path (open_entry: `open_commit`, the sections' openings, `note_unwrapped`, then `ingest` of the plaintext) leaves the removal's `secrets.0` boxes unopened or untaken where a plain ingest takes them. Until fixed, a sibling's concurrent removal is never covered at the other node: its account's fork is never merged (`signing_due` sees one head).

The duties test hands the commits over to test the pass-end rotation alone; once fixed, it should let sync carry them.
