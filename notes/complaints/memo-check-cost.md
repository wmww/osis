# memo-check-cost
> Summary: an unknown `OSIS_*` variable makes the sim harness exit 101 with no message; per-thread probe statistics never print from sim-sweep's job threads.

- A probe read through `OSIS_MEMO_*` made `sim-sweep` exit 101 after its first line, nothing said why (`testenv` refuses unknown `OSIS_` variables): name throwaway probe variables outside `OSIS_`.
- Thread-local `Drop` printing nothing from `sim-sweep` seeds: write probe counts from a global `Mutex` instead.
- A whole-binary `tools/icount` of osis `it` swings a few percent with thread timing; the sim scenarios are the stable yardstick.
- Review: an env-var probe (`MEMOPROBE`, read once into a `OnceLock`) let one build of each binary measure every schedule variant; a single-threaded osis `it` under `tools/icount` takes about 20 min at load but is stable.
