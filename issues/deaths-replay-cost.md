# Deaths replays left O(aspect history)
> Summary: A late writer delta replays only the window it can change (`retention/deaths.rs` `window`), but validity flips, a snapshot or import arriving, or one judged or dying after the late `ts` still replay every held body and the whole state; a window over a snapshot plays all its copies, and one over a residue-less dropped body joins the whole state.
> Tags: node, retention, performance

Repro: `cargo test --release --workspace --test it scale::late_delta_deaths_cost -- --ignored --nocapture` (`OSIS_SCALE_N`), alone after `free -g`.

Measured (N = 10^4, release, load 30-50): keep-at-least, a late delta 380 -> 6 ms, 5 in a batch 380 -> 35 ms, one 5 commits late 7 ms (no first-load spike: last deaths are persisted); compacted after the N commits, a late delta 240 ms, 5 in a batch 290 ms (the window plays the snapshot's 10^4 copies); notes/node.md, Deaths.

Left:
- Whole replay (O(held bodies + residues + state)): any validity flip on a bounded aspect, a snapshot or import arriving, a snapshot or import among the judged bodies, or one at or after the window's start with a death after the first late `ts`.
- A window reaching a snapshot or import plays every copy it carries (O(compacted state)), and one meeting a dropped body without a residue joins the whole state (O(state); common on keep-at-most aspects, cheap there).
- The window spans from the first changed body to its latest death: a late delta superseding a write that lived long (a map key written once and overwritten much later) replays every body in between.
