# Engine: the epoch rule
> Summary: How the engine keeps spec/permissions.md §5.4-§5.5 (`flows/account.rs`, `lists.rs`, `signing.rs`): the filter, name rows, the followed line, `JudgedEpochs`, what a node writes.

## The filter
- Runs first in each re-judge pass (`refresh_epochs`). A role commit that does not count stays held but no timeline reads it (`Held::set_counted`, left out of `HeldSet::edge_commits`). Every other part of a commit that does not count is invalid in `Judge::part` (`created.0` aside), but a plain part a counting addendum saves (`Vouching::saves`).
- Commits held nowhere (a relay-only signal, an inbox request) are judged whole by `Core::counts_at_epoch`.
- Addenda: one least fixpoint per thing over every author (perm `Timeline::vouching`, fed each addendum's standing). Monotone: addenda save plain content only, which neither a timeline nor an epoch reads. Tests: perm `content::addenda_fixpoint_runs_through_closed_epochs_*`, `rotation::tests_account::closed_epoch_write_falls_and_a_witness_saves_it_*`.

## Names
- Thing lists (`Engine::hold_lists`; `Engine::ingest_with_lists` holds a batch's list blobs before its rotation applies) and `listing.0` deltas (`lists::note_listing`) become name rows (`tn/` commit‖thing‖source, `tb/` source‖commit‖thing). Certs stay for good (`tl/`), as role commits do.
- A list for a rotation not held is not kept: node-sync keeps the entry as `Kind::List { held: false }` until the rotation arrives.
- Inner and merge signatures are kept per rotation (`ix.rotation_sigs`, persisted); merge signatures are verified at chain build (`osis_commit::verify_merge`).

## The followed line
- The default side (preferred by `Meta::received`) is recomputed alike after a restart, so nothing is recorded. A user's choice (`Engine::choose_line`) is kept with the admin sides (`sides::Sides::accounts`, `records::SIDES`). A node of the account sides by inner signature (`AccountView::authorized_by`).
- Rejected: siding with the rotations whose seed the node holds. A node removed while rotating minted a seed its siblings hold; a sibling that got that rotation first followed it against the merge for good.
- Rejected: no epoch open until a fork's merge. A removed node keeping its old key re-forks after every merge, and the account's content blinks out at every reader for good.
- The followed head's closers count too: a later merge's cutoff still runs from the other heads' receipt, so a removed node holding a sibling's concurrent epoch gains nothing.
- The chain is rebuilt when `account_view`'s key moves (held rotations, side, seeds, own D's roster).
- Doubt (`Chain::in_doubt`) is told once on its rise (`Event::AccountDisputed`) and listed (`Engine::account_disputes`); never at a node of the account.
- A merge finds heads by `at` and accepted names, never by a supersedes list, which a removed node's fork may fill (`a_removed_nodes_fork_is_merged_out_spec_permissions_5_4`).

## JudgedEpochs
- What the rule says per account is kept in `ix.epochs` and persisted (`node/epochs`): a standing is a lookup, and an open builds no chain and reads no list. `named` holds only held commits (`unindex_commit`), so it is bounded by the store.
- `refresh_epochs` takes the accounts due (`ix.epochs_due`, from `note_rotation`; `ix.names_due`: a commit at a closed epoch, or a word naming a held commit, arrived) and judges by `osis_perm::Epochs` only the commits whose standing may have moved (at a moved epoch, named by a rotation whose count moved via `tb/`, due, and what listings among them name). So a rotation costs the commits at the epochs it moved, a list the commits it names, a write no chain build (`rotation_judges_its_epochs_once_and_writes_stay_flat`, `a_rotation_lists_its_epoch_only`, `a_listing_named_late_names_again_spec_permissions_5_5`).

## Writing (`flows/signing.rs`)
- Removing a node from D rotates the account in the same transaction (`rotate_in`; thing lists inline only).
- Every rotation applied is due an answer, a listing or addenda (`ix.rotations_due`, `rd/`).
- A rotation a held removal still needs, or a fork's merge, is decided at the end of a complete pass of D's labels (`Engine::signing_due`, node-sync's re-seal pass), so a removal and its rotation arriving apart do not fork.
- Pairing carries the rotations with their lists (`Package::lists`), so D's earlier commits count at the new node.
- D is sealed to its nodes only (`Core::seals_to`). A node off D's roster drops the account's seeds and what it read as the account (`signing::leave_if_removed`; lost access and retain read `Core::member`, not `me`).
