# invites
- The engine facade tests write with `Engine::commit` (the raw commit), not `Engine::write` (the app's path), so a rule hooked on the app's write is invisible there until a test switches; easy to write a test that passes for the wrong reason.
- A cost count at only two sizes misled: adding n items under a new subgroup of a synced group read as superlinear "group index" work (105 at 20, 2005 at 200), but it is linear (2005 at 200, 20005 at 2000); the per-item factor is 5 or 10 between otherwise alike writes (fresh tids), so a 20→200 pair can show 19x.
- spec_map's stray-anchor check splits an anchor on `;`, so a glossed anchor with semicolons fails with a message that does not say why.
