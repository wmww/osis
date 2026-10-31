# text-session-gaps
- Masonry 0.4's `TextArea` has no selection getter, so keeping a caret across a remote merge needed vendoring all of `masonry` (kit/patches/masonry) for a five-line accessor.
- Adding a `[patch.crates-io]` entry makes `cargo test --locked` in kit fail until the lock is refreshed once without `--locked` (`cargo metadata` does it).
- (reviewer) The worker did not run tools/spec_map.py --uncited (the gate's first check): four new tests without a citation failed the first gate.
