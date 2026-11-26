# held_set_decides_plain misses its Settled coverage floor
> Summary: `order::held_set_decides_plain` fails its coverage floor on main at some offsets: its Settled-emphasis seeds ran, but none judged a settled history before its exchange with held-model judging a live body dropped as covered, so within 8 seeds the generator does not reliably reach a covered drop of a live body.
> Priority: normal
> Tags: tests, engine

- Replays on main (f5bcabb26, and before 026decfa4): `OSIS_ORDER_START=527365123458 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` panics in `Seen::floors` (`order.rs`, the `Emphasis::Settled` floor: `s.settled > 0` and held-model's `live drops judged` > 0); every history passed its checks. Listed in tools/known_failures.txt.
- Either the Settled emphasis should reach a live covered drop by construction in every seed that has one (then find the step that stops it with `OSIS_ORDER_STATS=1` at that offset), or the floor asks more than 8 seeds give. A floor met by too few seeds per run is drawn on purpose (notes/test-harnesses.md), not by more seeds.
