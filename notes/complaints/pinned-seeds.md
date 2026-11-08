# pinned-seeds
- `tools/bin-at` leaves main's binary at the branch's `target/debug/deps/it-*` path until the next build: copying "the new binary" right after it copies main's (same hash name). Rebuild before copying.
- Most pinned `check(seed, ..)` histories no longer reach what their comments describe (Aim retargets steps as the generator changes); converting one needs a probe first, so deleting was usually the honest choice.
