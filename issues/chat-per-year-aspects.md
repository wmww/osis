# Chat builds a new aspect name every year
> Summary: osis-chat writes messages on `chat:msgs:y<year>.0`, a name built at run time, to cap a rebuild cost the engine has since fixed. It breaks at new year, breaks the static-aspect rule (notes/api-design.md) and dragged prefix matching into required retention. Fix: one `chat:msgs.0` declared in `schema/chat.osis`; delete every trace of the year split and of what existed only for it.
> Priority: normal
> Tags: chat, api

## What is wrong
- **Why it exists**: every validity flip (a kick) rebuilt an aspect from all its held bodies, so a kick in a chat of 10^6 messages was estimated at about 70 s (never measured). A name per year capped that at one year. That cap was a guess: nobody knows how many messages a chat gets in a year, and if 10^6 over years is too slow, so is 10^6 in one year.
- **The cost it capped is fixed in the engine**: a register's rebuild stops at its winner (`Fragment::settled_above`, issues/node-core-gaps.md), and a message is a scalar register write. That fix landed before osis-chat; the split was kept from the earlier design. What still grows with a long aspect (issues/long-aspect-cost.md) is per thing (`rejudge_all` walks the thing's commits, open, frontiers) or per kicked delta. The split never helped either.
- **It breaks at new year**: `on_event` subscribes to the creation year up to next year, so an app left running past the following new year hears nothing new. A device whose clock is over a year ahead writes where nobody reads. Manual testing never sees either.
- **It breaks the model**: aspect names are static, declared in a schema. Chat has no schema and builds names with `format!` through `Osis::aspect_key`.
- **It spread**: ids carry the year (`YEAR/TS/COMMIT`), purges and reads loop over years, and required retention matches AK *prefixes* (longest match) only so one rule covers the year family (notes/permissions.md Required retention says so). Without families an exact AK does the same, and the empty prefix meaning "every AK" is the magic-value pattern notes/api-design.md flags.

## Fix
1. `schema/chat.osis` declaring `chat:msgs.0` and `chat:settings.0^`; libs/chat generates keys from it in a build script (schema/README.md), like app/ does for contact and event. No `aspect_key` call left in libs/chat.
2. libs/chat: one message aspect. Delete `year_of`, `years`, `year_key`, every per-year loop, the multi-subscription `on_event` (one `Subscription`, not a `Vec`), the renewal caveat. `Id` is the history position alone (`TS/COMMIT`). Update app/ and cli/ callers.
3. Required retention by exact AK: `RequiredRules { rules: BTreeMap<Ak, Required>, default: Option<Required>, retain_copies }`, rewriting spec/commits.md §5, spec/data-model.md §9, `osis::core`, the engine's `in_force`, and notes/api.md and notes/permissions.md. Must pass notes/api-design.md.
4. Tests: delete `across_a_new_year_spec_data_model_2` (libs/chat flows.rs); rename the year-style AKs in core/node/tests/it/required.rs, core/test/sim/tests/it/scale.rs and the engine's `forget_live_walks_no_other_bodies` to plain static names.
5. Measure: add a kick to `scale::long_aspect` (one register aspect, 10^5 at least, 10^6 if memory allows) and record the number in notes/testing.md and notes/chat.md Costs. A cost that is too high goes to issues/long-aspect-cost.md and is fixed in the engine.

## Why it will work
Messages are scalar register writes, the case the engine's winner stop covers, so a kick reads down to the newest valid message instead of the whole aspect. Every cost the split did not help stays as it is. Nothing is migrated: no release, no compatibility (CLAUDE.md). If the measurement surprises, the engine is the place to fix it for every app; a long aspect is not chat-specific.

## Done means gone
Everything that existed only for the split is deleted, not deprecated or noted: code, tests, the prefix matching, and every mention in notes, spec, issues (notes/chat.md, notes/chat-cases.md footnote 32 and the per-year estimate, notes/permissions.md, notes/api.md, issues/api-deferred.md's per-year subscription line) and comments. Afterwards nothing in the tree mentions years for aspects or explains why there is a single aspect; the static-aspect rule in notes/api-design.md covers it. Delete this issue; then `grep -rniE 'per-year|msgs:y|YEAR/' .` finds nothing.
