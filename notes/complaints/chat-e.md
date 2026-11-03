# chat-e (tiller-chat-e)
- The task named examples/chat and said to remove its code: it went in 69574b7b (`git log`); only a sim scenario keeps the persona shape. Then the crate moved to core/chat mid-task.
- A global clap flag eats a subcommand's flag of the same name: `chat read --limit` with a default of 50 set the materialization bound to 50 bytes, `TooLarge` on every read. `--max` it is, as `commits` does; nothing warns.
- A background `cargo ... | grep` shows nothing until it ends; a timeout kills it with nothing to show: write to a file. Lost 10 min of a measure so.
- 100 members on the sim took over 20 min before the first message; the 10^4 run did not finish. See issues/chat-add-cost.md.

## API annoyances (for issues/api-review.md)
- `replace` of a `Value::Map` on a long aspect costs a write O(writes so far), a scalar stays flat: nothing says so. A kept-write aspect wants a scalar.
- `set` of an equal value writes nothing, so `at.set` silently loses a repeated message: a kept-write aspect must use `replace`. Not wrong, but the first thing one reaches for.
- `FOREVER` was not exported from `osis` for `Retention.at_least` (added).
- No `at.history_entry(id)`: `history_entry_here` exists inside; a lookup is `After(HistoryPos::time(ts))` and a walk, and so an id must carry its `ts` and the aspect.
- `HistoryBody::Purged { by }` names a commit; who deleted needs a commit query with no by-id filter.
- `aspects(t)` may not list a register whose last write was purged; the library walks years from `created` rather than trust it.
- `on_history` is per aspect, so a per-year chat holds a subscription per year, none for a year beyond next.
- `osis::schema::core_types::RequiredRules` written whole for one field; `set_keep_default` exists, a `set_required` would not save much.
- `members` shows K for a link's joiners; `holder_path` goes one way only, there is no "who holds through this" call.
