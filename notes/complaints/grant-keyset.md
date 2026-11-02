# grant-keyset
- `gen-vectors -- corpus` rewrote 14 unrelated fuzz seeds (box, proto_frame, step: random bytes per run) besides the schema_dsl ones the change needed; had to restore them by hand. The corpus generator is not deterministic for those targets.
- `timeout 600 core/test/tla/run.sh small | tail` lost the whole output when the timeout hit at load 40 (run.sh small took 12 min, not "about a minute"); write it to a log instead.
- The judgment vectors change for any schema change (bundle bytes and `read=` hashes), not only for judgment changes: checking "did judgments change" needs a hash-normalized diff of the verdict lines.
- Gate took 1074 s at load 50+ (mostly the post-rebase rebuild and tier 1).
- (review) The perm tier-2 command at load 30-50 took 470 s wall (221 s in the one test binary that runs anything; the rest is building/launching 15 binaries that filter everything out).
