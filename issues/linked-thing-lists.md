# Linked thing lists are decoded but neither written nor read
> Summary: spec/wire.md §4 lets a `ThingList` hold its commit IDs as a LINK (above `CHUNK_THRESHOLD`); osis-commit decodes `ListIds::Linked`, but the rotator writes inline lists only and the engine takes names from inline lists only. Choose: implement both sides, or drop the LINK case from the wire and spec.
> Priority: low
> Tags: perm, engine, spec

## Today
- Writer (`flows::signing`, `rotate_in`): `fit_list` runs with `CHUNK_THRESHOLD` (128 KiB, about 3,900 IDs), not spec/permissions.md §5.5's `MAX_LIST_BYTES`; a rotation whose role and purge commits alone pass it on one thing is refused (`Misuse`). Plain content past it goes to later listings as the spec says.
- Reader (`flows::lists::keep_certs`): a linked cert is verified and kept, but its names are not recorded, so the commits it names read as unlisted. Only a list's own rotator can write one, so a peer can hide only its own account's commits, which it could do by omitting them; no peer makes another account's commits read wrong. Between nodes of this build it never happens.

## Choice
- **Implement**: write a list above `CHUNK_THRESHOLD` as a chunk tree keyed by the thing's dedup secret (as a linked frontier), and read it in `keep_certs` (fetching the tree, which then waits on blobs). Raises the specials bound to `MAX_LIST_BYTES`.
- **Remove**: `ThingList` is `[tid, [commit_id*], salt]` only, `ListIds` goes, and the spec bound becomes `CHUNK_THRESHOLD`. Simpler; the only loss is rotation past about 3,900 role and purge commits on one thing since the last rotation.

No backward compatibility is needed either way before stability.
