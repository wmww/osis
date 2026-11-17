# Account signing: what is left
> Summary: Outsiders verify a commit by its account's signing chain (epochs whose keys every node of the account holds); the node's own signature travels sealed to the account's nodes. Built and specified (spec/permissions.md §5.4-§5.5, spec/crypto.md §9; notes/engine-validity-epochs.md). Left: re-added nodes in listings, judgment and own cover's scan costs, commit growth.
> Priority: normal
> Tags: perm, crypto, sync, spec

Model: roles-model `custody` and `epochs` (README there). Decided design and rejected alternatives: spec/permissions.md §5.4-§5.5, notes/engine-validity-epochs.md.

## Left
- **Re-added nodes in listings** (spec/permissions.md §5.5 Listings: "every commit by a node that was removed from D and is a node of P again"): not built, and not modelled (roles-model has no honest re-adds; custody models X's). Model first. A simpler rule to try there: a node coming back onto D's roster answers every counting rotation again, naming its own commits by inner signature (it was off the roster when they came, so it answered them with nothing).
- **Judgment cost**: `JudgedEpochs` keeps each closed epoch's closers, O(rotations) per epoch, so O(rotations²) per account, rebuilt and persisted whole on each rotation (rotations, not commits; fix when a chain grows long).
- **Same-millisecond cutoff**: the cutoff compares receipt wall ms strictly, so a commit received in the same ms as the earliest closer is named only by its author's listing.
- **Own cover's scan**: `signing::own_covers` reads every aspect with a held snapshot or a forgotten commit stamped since the oldest epoch the rotation closes opened (the first epoch: every such aspect), each one's state, at every plain rotation: O(those aspects of the node), not O(P's). Rare (removals, pairings, answers); index carried-only writes by author if it shows.
- **Commit growth**: signing as an account grows a one-field commit by 131 B over a key actor's (the inner signature 95 B, the epoch's ID 32 B, heads; `an_accounts_one_field_commit_grows_by_its_signing_fields_only_spec_wire_4`), past the 100 B once aimed at. Only shrinking the inner signature (its signer's tid, its tag) would reach it.
- **Thing list cost**, measured (`a_removals_lists_cost_a_path_per_thing_and_an_id_per_edit_spec_permissions_5_5`): about 1.3 KiB per thing a removal lists (its 32-hash path 1,088 B) plus 34 B per commit, the same at 2 and 20 things. That is the shape spec/requirements.md Cost asks for (per thing edited, by its edits, nothing by history); sharing path prefixes within a list blob would save only about 34 B per level of the log₂(things) the paths share, so it is not built.
- Where node cards and `reach.0` are held is the reference graph's (spec/sync-set.md §1: a node thing's card under D's sync ID).
