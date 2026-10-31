# eph-unify-3
- Required reading was about 300 KB of notes (ephemeral.md and node.md near 100 KB each, testing.md 90 KB): a large share of a worker's context before any code.
- Tier 1 took 4.5-6 min at load 30 (notes say 45 s quiet); clippy after it 17-30 s.
- `#![forbid(unsafe_code)]` rules out `std::env::set_var` in tests, so finding which transaction wrote durably took a temporary static flag in osis-store; a test-only "fail on durable write" hook on `MemoryBackend`/`Faults` would have made it one line.
