# Moving a favorite held twice in one list leaves it in place
> Summary: Two nodes favoriting the same thing at once leave two entries in one favorites list; `Data::move_favorite` (libs/kit/src/store.rs) moves the first entry only, and `favorites()` shows the thing at the other entry, so the drag does nothing. app `sync::favorite_twice_then_moved` fails on main.
> Priority: normal
> Tags: kit, app, tests

`favorites()` dedupes by first occurrence; `move_favorite` moves `shown.position(x)`, one entry of possibly several. A fix moves (or drops) every entry of `x` in the list in the same write; `toggle_favorite` already removes all of them.
