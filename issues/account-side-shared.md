# An account fork's side is per node, not per user
> Summary: The version of a forked account a reader follows (spec/permissions.md §5.4, Placing) is chosen per node: by default the first held there, a user's choice kept in the node's local sides record. Tess's rule is per user ("they stay on the one of the first revocation they saw"), so it belongs in the account settings (issues/settings.md), not built yet.
> Priority: normal
> Tags: perm, api, settings

Stage A4 (notes/redesign-plan.md) deletes account sides: an account fork becomes an admin dispute whose side a node takes by first received (notes/write-path-design.md §1 F1 to F5). Read again there; nothing to build before.

## Now
- Default: each node of the reader's account follows the version it held first, so two of the user's nodes may follow different versions (each warned, each choosing separately).
- Choice: `Osis::choose_side` → `Engine::choose_line`, kept in `sides::Sides::accounts` (`records::SIDES`), this node only; recomputed default after a restart from the receipt order.

## Target (once issues/settings.md is built)
- The first node of the reader's account to follow a version of a forked account writes it as an account setting (`settings` thing, key per forked account), and every node of the account places that version's line first, as a user's choice. A user's switch writes the setting.
- Two nodes writing the setting at once: the setting's merge picks one, which one node then follows instead of its own first-seen line: one switch, made by the user's own nodes agreeing, never back and forth by itself. State that in spec/permissions.md §5.4.

## Sync side
Nothing new: readers learn an account's rotations as header-only certificate copies under the sync IDs the account's nodes open (spec/permissions.md §5.5, Chains travel), the rejection that raises the warning among them. A peer delaying the revocation makes a reader follow the removed node's fork (stated in §5.5). Sync must keep delivering an account's rotations to every reader of a sync ID the account writes under; no sync world test checks it (issues/sync-tests-owed.md).
