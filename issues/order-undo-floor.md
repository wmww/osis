# held_set_decides_plain misses its step-kind floor for Undo
> Summary: `order::held_set_decides_plain` fails its coverage floor on main at some offsets: none of 10 Undo steps made a commit (every step kind tried ten times or more must reach a commit), so the generator does not reliably aim Undo at something undoable.
> Priority: normal
> Tags: tests, engine

- Replays on main (2efb5541f): `OSIS_ORDER_START=776032563648 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` panics in `Seen::floors` (`order.rs`): "none of 10 Undo steps made a commit"; every history passed its checks. Listed in tools/known_failures.txt.
- Cause not yet found: `aim` already points an Undo at an own undoable commit; at this offset every one made no commit (no change, the listed outcome).
