# Engine: re-judging validity
> Summary: What `rejudge_all` (`apply/validity.rs`) judges again after a held-set change, so the cost follows the change; per-commit cost; addenda by header; debug checks; possible holders.

## What is re-judged
- Authors whose role may have moved, on the things it may have moved on (`Core::stale_authors`, `stale_under`: `Held::upstream` and `Held::reach` of what `osis_perm::Changed` reports, via `ix.by_thing`). A thing holding addenda is judged whole: an addendum vouches for others' deltas.
- Commits whose writes apply otherwise whoever signed them (`Changed::commits`: an invite grant overtaken on its grant loses its boxes' exemption with no role of its author moving). Never every commit on a changed edge: a long role history would re-judge all its holder's writes per arrival.
- Every delta on the things a component walked anew or a new record's chain reaches (`Core::stale_things`).
- Commits whose void, required-role or overreach inputs changed (`stale_commits`), and those acting for a thing whose timeline changed (`acts_for`).
- Everything after a rebuild at open (`stale_all`).

No delta's validity depends on its thing's `retention^.0` setting: a setting is judged as an admin-only delta and only moves what history keeps (notes/engine-retention-history.md). A rollback restores validity flags with the journal.

`rejudge_all` repeats while a rebuild left something stale (a part `retention::uncover` made missing); it ends, as `uncover` never turns parts back.

Rejected: re-judging every held delta per role commit (O(held commits) each); a grant re-judges no content commit (`scale::grant_is_flat_in_content_commits`).

## How perm reports moves
`Timelines::update_touched` re-partitions around the things whose held inputs changed (`Held::take_touched`; a commit naming only things of its component continues the walk instead, `Timelines::append`). A component evaluated anew re-judges all its things; one whose walk only went on or gained leaves, only what authority flows to from the touched things (`Held::reach`). So a new thing, or a grant to a holder new to every walk, re-judges that thing's deltas only.

## Cost per commit
- `Judge` takes each commit once, looks record depth and the timeline up once per thing, and answers an author's deltas from where it holds the role (perm `Timeline::valid_from`, once per (thing, author, role)). A voided commit is re-judged alone.
- Possession signatures are verified once per (signature, key) while their part is held (`Showing`'s `Verdicts`, a function of bytes alone; `a_possession_signature_is_checked_once_spec_crypto_4`).

## Addenda by header
An addendum's validity reads its header and the timeline, never its body: `ix.addenda` holds every held commit's `addenda.0` delta from its header (`validity::note_addenda`, also at open for a body not held), with its entries only while the body is held (`forget_addendum_body` on drop or strip, before its `node/addenda` row is rewritten). So the persisted row equals what a rebuild reads (`tests_addenda::a_bodiless_addendum_is_judged_by_its_header_spec_perm_5_2`).

## Checks
- Debug builds assert at each transaction's end that nothing stale is left and no flag changed outside the re-judged set.
- `Engine::misjudged` (in `Engine::check_index` and the order harness after a reopen) checks each flag is what judging gives. Judgment inputs from a body (rotation role, overreach, possession shown) are persisted in the commit's `node/metas` row, so this holds with the body dropped.
- perm `incremental::incremental_equals_from_scratch` checks reported moves against every timeline answer (`update_moved`). Arrival order: `apply/tests_order.rs`, perm `incremental` late leaves, `late_holder_judges_revoke_alike_*`.

## Possible holders (`Held::ever_admins`, `ever_writers`)
The one helper for "could this signer ever have held the role" where the answer must not depend on arrival (purge rights; spec/commits.md §4); a timeline read would. A least set grown from the thing through first admins and grants signed by members, of any validity, so it only grows. One set over the thing and its members, not one per member thing (a member could name the holder on the thing anyway; per-thing sets took 20 s per call on a chain of 1000 groups).
