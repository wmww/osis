# invites
- The engine facade tests write with `Engine::commit` (the raw commit), not `Engine::write` (the app's path), so a rule hooked on the app's write is invisible there until a test switches; easy to write a test that passes for the wrong reason.
- Baseline cost: adding n new items under a new subgroup of a synced group costs ~n·(n/10) "group index" work at n=200 (105 at 20, 2005 at 200) before any marking; looks like the kept synced closure being copied/edited per add. Not investigated.
- spec_map's stray-anchor check splits an anchor on `;`, so a glossed anchor with semicolons fails with a message that does not say why.
