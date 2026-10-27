# Deaths replays left O(aspect history)
> Summary: A late writer delta replays only the window it can change (`retention/deaths.rs` `window`), but snapshots or imports at or after the window, a residue-less dropped body in it, and validity flips still replay every held body and the whole state; the first window per aspect per session loads every held body's death record.
> Tags: node, retention, performance

Repro: `cargo test --release --workspace --test it scale::late_delta_deaths_cost -- --ignored --nocapture` (`OSIS_SCALE_N`), alone after `free -g`.

Measured (N = 10^4, release): a late delta 380 -> 6 ms, 5 in a batch 380 -> 15 ms, one 5 commits late 2 ms (110 ms the first time in a session: `Lasts` loads); notes/node.md, Deaths.

Left:
- Whole replay (O(held bodies + residues + state)): any validity flip on a bounded aspect, a snapshot or import arriving, a late delta when a snapshot sorts at or after the window's start (every late delta older than the aspect's last compaction), or a dropped body in the window without a residue (common on keep-at-most aspects; cheap there, few bodies held).
- `Lasts` loads every held bounded body's death record once per aspect per session (about 11 µs each; a failed transaction keeps it, journaled), and stays in memory (O(held bounded bodies)); a persisted index by last death would avoid both.
- `window` scans the commits after its start in memory for snapshots and imports (O(bodies after it)).
- The window itself spans from the first changed body to its latest death: a late delta superseding a write that lived long (a map key written once and overwritten much later) replays every body in between.
