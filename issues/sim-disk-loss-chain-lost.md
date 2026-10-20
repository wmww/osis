# A device lost before its uploads are confirmed can leave its commits unverifiable
> Summary: `disk_loss` fails 12 of seeds 1..50 (main before sync round 2: 6): the device recovered from the card cannot `recover` ("the card's key does not own the person") because the person's creation commit stays pending `MissingChain` of the recovery key actor: a chain record the lost device placed is not at the server, and no other node places it.
> Tags: sync, flows, tests

Repro: `cargo run --release -p osis-sim --bin sim-sweep -- --seeds 50 --only disk_loss`, or `osis_sim::replay("disk_loss", 3)`. Possibly one family with issues/sim-two-devices-seed-11.md.

- Seeds failing on this branch: 3, 6, 7, 10, 14, 17, 18, 21, 27, 28, 37, 43 (`osis_sim::replay("disk_loss", 3)`); on main at a780cf0: 10, 14, 18, 21, 26, 28.
- Seen in seed 3: the fresh node opens all 35 entries of the home label; 19 commits pend `UnknownCreated`/`MissingChain`, among them the person's creation (chain of the card's key actor). The lost device's last Upload was cut with the connection just before the loss; the remaining device (a writer of the home label) holds the records but only places its own chain certificates (spec/permissions.md §4 is per node).
- The in-flight upload tracking of sync round 2 (no re-send before an answer or 30 s) makes the window larger, hence the higher rate; the gap exists on main too.
- Fix direction: a member holding a commit whose author's chain certificates are missing under the label places them (as it does for revokes and roster snapshots, §4), or the recovery flow fetches the chain from any server holding it; or the scenario waits for the lost device's uploads (it models a device lost mid-sync on purpose).
