# parsed-keys
> Summary: complaints from the parsed-keys branch.

- No valgrind on this box: caller attribution needs tools/cpuprof samples, a few hundred per median test, so shares under 1% are noise. A small script that counts caller chains above a frame (what `callgrind_annotate --tree=caller` gives) would belong in tools/cpuprof_report.py.
- `cargo test --workspace --no-run` builds the GUI too (minutes); for a core API change `cargo test --no-run` (default members) is the right check.
- Review: the branch's own key-check comparisons covered the boundary and random inputs but not every torsion encoding with the sign/top bit set; the reviewer widened both to exhaustive sets (all 14 rejected X25519 strings counted).
- Gate limits again (as possession-role): `gate.hold` 3795 CPU-s / 241 s wall and `gate` 4094 / 299 s sit below the sum of their own stages' limits (default-tests + properties + sim: 11845 CPU-s); every stage was inside its limit, the totals flagged 2.3-5.2x. Clippy flagged 3.3x at load 34 (shared box).
