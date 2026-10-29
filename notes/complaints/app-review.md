# app-review complaints
> Summary: footguns met reviewing the app prototype.

- `db.groups_of(t)` follows membership only: a tag that is just a subgroup of another tag does not list it. Easy to assume it covers subgroup edges (cost a debug round in `Data::delete`).
- `Osis::knows` stays true after `Write::delete`; "is it still there" needs another check.
- Two-device tests in app/ need core's `deliver` re-written (engine-level, `#[doc(hidden)]` `Osis::engine`); the server-backed `World` harness is core-test-only.
