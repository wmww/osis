# Three tier-2 scale checks fail
> Summary: `scale::big_set_by_value_cost` and `scale::text_range_and_edit_cost` fail with `Permission` on a commit in a reopened session (set remove by value; a text delete or move), and `scale::roster_removal_cost` fails because its extra `secrets.0` write no longer fits the core type (`Malformed("a value the core type does not take")`). Their cost figures in notes/engine-paged.md, notes/testing.md and notes/chat.md cannot be refreshed until they run.
> Tags: tests, node

Repro: `cargo test --release -p osis-node --test it -- --ignored --nocapture --test-threads=1 scale::big_set_by_value_cost scale::text_range_and_edit_cost scale::roster_removal_cost`.

- `big_set_by_value_cost`: add new and add present pass (2 pages each), then `remove` by value in a new session returns `Err(Permission)` at scale.rs:356.
- `text_range_and_edit_cost`: reads and inserts pass, then a delete or move in a new session returns `Err(Permission)` at scale.rs:524. Both reopen through `Reopen::open`; whether the engine or the harness is wrong is not known.
- `roster_removal_cost`: the rotation part passes (roster 100: 279 KB, 2820 B per remaining holder); the extra write `secrets.0` field 1 key `Int(999999)` = 64 bytes is refused by `check_types` (scale.rs:295): the test must write a well-typed history box.
