# General API review
> Summary: Tess's whole-API review, to do with her: names and shape of the public `osis` API, CLI and the spec words behind them. Collects renames so they land together, after the other coordinator's engine and permissions wave, and talked through with Tess before executing.
> Tags: api, spec, naming

Renames:
- issues/account-rename.md, issues/grant-rename-multi-actor.md.
- "Placement" (Tess): it means making a thing an item or subgroup of a group, but implies a thing has one place, and it can be in many groups. Say a thing is a member of a group, added to or removed from it. Touches `place`, `place_expiring`, `unplace`, `place_plan`, `placed.0~`, tests, about 120 spec lines, about 480 notes lines, over 150 code files. Sync's separate word "placed" (a commit held at a host, spec/sync.md §5) goes too; "uploaded" or "at a host". Spec prose already defines "member" as this relation (spec/permissions.md §1). A chat's member (an account with a role) is a different thing, so app docs keep them apart.

Shape, left for this review: issues/api-knows-empty.md, issues/api-leaving-give-up.md, issues/api-deferred.md. Undo's redesign was deferred to it too (notes/mvp-progress.md).

## From building osis-chat (not re-checked one by one)
- `replace` of a `Value::Map` on a long aspect costs a write O(writes so far), a scalar stays flat: nothing says so. A kept-write aspect wants a scalar.
- `set` of an equal value writes nothing, so `at.set` silently loses a repeated message: a kept-write aspect must use `replace`. Not wrong, but the first thing one reaches for.
- `FOREVER` was not exported from `osis` for `Retention.at_least` (added).
- No `at.history_entry(id)`: `history_entry_here` exists inside; a lookup is `After(HistoryPos::time(ts))` and a walk, and so an id must carry its `ts` and the aspect.
- `HistoryBody::Purged { by }` names a commit; who deleted needs a commit query with no by-id filter.
- `aspects(t)` may not list a register whose last write was purged; the library walks years from `created` rather than trust it.
- `on_history` is per aspect, so a per-year chat holds a subscription per year, none for a year beyond next.
- `osis::schema::core_types::RequiredRules` written whole for one field; `set_keep_default` exists, a `set_required` would not save much.
- `members` shows K for a link's joiners; `holder_path` goes one way only, there is no "who holds through this" call.
