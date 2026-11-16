# keel-kit-trim
- app `sync::favorite_twice_then_moved` fails on main before any kit change (issues/favorite-duplicate-move.md); `cargo test -p osis-kit -p osis-app` without `--no-fail-fast` stops at it and skips kit's tests, which reads as kit passing.
- tools/policy.py also checks notes' code names: moving a type (`KeyedList`) is a notes edit too, found only by diffing policy output against the main checkout's (policy is red on main, so its exit says nothing).
