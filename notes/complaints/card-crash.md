# card-crash
> Summary: Footguns met fixing the differential's pairing-on-a-failed-store class.

- The engine's index check copies the live `Core::accounts` into the fresh core it compares against (`checked_index`), so a seed a failed transaction left in memory showed only through the epochs index it feeds; a field the check copies is one it cannot catch.
- The engine's end-of-life check runs when the harness drops a crashed node before its owed reload: the first sign of the inexact rollback came from a power-loss sweep over every write, not from any engine failing-write test (those retry before checking).
- A sweep over every durable write of a harness `pair` is 93 writes, most of them sync's step after `Input::Wrote`, about 0.13 s each: too slow for a default test; the per-write sweep lives at engine level, where pairing is 10 writes.
