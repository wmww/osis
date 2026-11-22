# order-fails
> Summary: Footguns met fixing order:: property failures.

- A `settled` seed's shrink keeps its ~800-step tail whole and spends the whole `SHRINK_CANDIDATES` budget on the head (8 minutes for 878 -> 830 steps); the shrunk head was still the useful part, but the printed `h` is mostly tail.
- `OSIS_ORDER_DUMP`'s `explain` builds its own keep-everything node (no `pass_end` before `walk_sides`), unlike `oracle`: it showed no index differences where the oracle's node differed. Comparing the oracle's construction step by step (made/fresh, keep_bodies, pass_end, walk_sides) found the cause in minutes.
- The one-path panic happens inside generation (`play_in`), so every candidate of its shrink replays the full delivery checks of non-failing candidates: slow for a panic found in 0.4 s.
