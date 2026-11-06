# first-admin-c
- `core.osis` still named `created.0` field 0 `owner` and listed a field 3 `admin`, while code and spec/wire.md §3 use 0 admin, 1 key, 2 nonce: nothing checks the schema text against `CreationRecord`, so it went stale silently (the CLI's `show` printed `{owner: ...}`).
- The fuzz corpus on main was stale: `gen-vectors -- corpus` also rewrote `creation_record/` and `tid_parse/` seeds this branch did not touch (an earlier tid vector change was never followed by a corpus regeneration). Nothing flags a corpus out of date with the vectors.
- A scripted rename to `Records` (perm) collided with a private `type Records` alias in `walk.rs`; renaming a local `owners` to `chain` shadowed a later `chain` binding in `flows/edges.rs`. Clippy caught both, but the collision check in notes/build.md "Scripted renames" should include type aliases and later bindings in the same function, not only files holding both words.
- Tier 1 took 715 s at load 20-22.
- Reviewer: gate took 691 s at load 24 (base crates renamed: full rebuild). Plain order run at offset 7300 hit a seed that fails on main too (issues/record-only-order-seed-7300.md); `tools/bin-at main` settled it in 2 min.
