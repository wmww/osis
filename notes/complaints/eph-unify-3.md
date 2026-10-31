# eph-unify-3
- Required reading was about 300 KB of notes (ephemeral.md and node.md near 100 KB each, testing.md 90 KB): a large share of a worker's context before any code.
- Tier 1 took 4.5-6 min at load 30 (notes say 45 s quiet); clippy after it 17-30 s.
- `#![forbid(unsafe_code)]` rules out `std::env::set_var` in tests, so finding which transaction wrote durably took a temporary static flag in osis-store; a test-only "fail on durable write" hook on `MemoryBackend`/`Faults` would have made it one line.
- Review: the branch predated the receipts-only merge, so the rebase hit a conflict in receipt.rs and a main test using `Receipt::nodes`; the first gate failed on `spec_map --gaps` (the new session-form MUST had no RULES anchor): workers adding a MUST should run `python3 tools/spec_map.py --gaps`.
