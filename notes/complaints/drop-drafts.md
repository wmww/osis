# drop-drafts
- `tools/spec_map.py` keys a RULES anchor on exact spec words: rewording a MUST sentence breaks `--gaps` until the anchor in the script is edited too (found only by the instant checks at the end).
- Removing a no-op commit (`Osis::persist` on a durable thing drew a header blind from the engine rng) shifted rng draws and made a seed-sensitive chat test (`link_joiner_leaves_spec_perm_7`) hit a known split bug; telling that from a regression took a `tools/bin-at main` build.
- Tests that flip "the last byte" of a commit blob (`synthetic::diagnostics_deduped`) depend on the blob's trailing field; a format change silently turns them into a different case.
- Review: tools/gate.sh runs tier 1 without --no-fail-fast, so a known failing test (link_joiner_leaves) skips unification, schema, deny, sweep and kit; ran those by hand from a copy of the gate's steps.
- Tier 1 `--no-fail-fast` took 567 s wall here (box shared with other agents), about 4x the 2.5 min note.
- Review 2: sim-sweep `ephemeral` seed 15262193248 failed "node 0 is down": `window()` went on after a crash in the sync step following its write (harness, not engine).
