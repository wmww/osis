# g-carriers-review
- Forging a sealed fire with an extra chain commit needs `Engine::fire_keys` (made `pub(crate)`) and a copy of `sealed_fire`'s sealing steps; a test helper that seals a given `SealedFire` would make hostile-fire tests one call.
- `osis_schema::core_types::Frontier` has no `covers` (that is `osis_perm::Frontier`): tests read `.commits.contains`.
