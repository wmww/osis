# sealer-mark
- The issue's repro seed (515999791879) already passed on main: the stale-box Seal skip had closed that history. The livelock needed a removal going alone to show in a default test.
- A new keyset field must be added in three places that do not reference each other: `ct::Keyset` (Rust), `schema/core.osis` (else every `keys.0` write fails validation as `NoEpoch(Read)`, a confusing error far from the cause) and the test vectors.
- The property's blind excuse was reached by none of 1000 seeds (`record` skips actors with holder actors), so its narrowing is checked by nothing the generator reaches.
- Review: a test kept passing by changing an rng draw ("by the same luck") instead of pinning what the draw decided: a pass places bodies in commit-ID order, so the test now writes until one sorts after the rotation.
