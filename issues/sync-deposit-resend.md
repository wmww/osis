# A non-writer re-deposits every pending deposit on each pass
> Summary: `pass.rs` sends a `Deposit` for every own unstamped entry not yet present at the server; nothing remembers deposits in flight, so each pass started before the server's push arrives sends them all again. A reader granted on a group applies ~15 commits, each starting a pass: 15 blobs go out 120 times (~280 KB instead of ~25 KB), quadratic in the burst.
> Tags: sync, node

- Seen through the example apps (examples/folder, osis-sim `World::start_tally`/`tally`): after `grant(root, bob, Read)`, Bob's node sends 120 `Deposit` frames under the root's label, the same 15 blobs 15, 14, …, 1 times. Writers have the same gap for uploads (issues/sync-upload-resend.md). It also costs CPU: a read grant takes seconds in a debug build, which is most of the folder and chat e2e time.
- The server treats repeats as duplicates (no storage harm), but the bytes count against the per-label deposit budget's rate and every repeat is verified.
- Fix (node-sync, `Engine` pass): keep deposits in flight per (server, label, blob) until the server's add event or an error answers them; skip those in later passes; drop the mark on disconnect.
