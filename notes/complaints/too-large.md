# too-large
> Summary: footguns met mapping engine errors to API errors in one place.

- The brief said keep to core/osis, but osis's `Error::TooLarge { limit }` needs the bound and the engine's `Data(TooLarge)` neither carried it nor told a read bound from a format cap (claim set, sealed fire): the one-place fix needed a small engine variant (`PastBound { bound }`).
- osis's lib has `test = false`, so a plain conversion test goes in `tests/it` through `osis::internals::engine`; osis-crdt's error types are not reachable from there.
