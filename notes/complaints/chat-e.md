# chat-e
> Summary: API annoyances from chat-e, to move into issues/api-review.md (not re-checked one by one).

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
