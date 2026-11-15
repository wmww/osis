# An account fork's side is per node, not per user
> Summary: The version of a forked account a reader follows (spec/permissions.md §5.4, Placing) is chosen per node: by default the first held there, a user's choice kept in the node's local sides record. Tess's rule is per user ("they stay on the one of the first revocation they saw"), so it belongs in the account settings (issues/settings.md), not built yet.
> Priority: normal
> Tags: perm, api, settings

## Now
- Default: each node of the reader's account follows the version it held first, so two of the user's devices may follow different versions (each warned, each choosing separately).
- Choice: `Osis::choose_side` → `Engine::choose_line`, kept in `sides::Sides::accounts` (`records::SIDES`), this node only; recomputed default after a restart from the receipt order.

## Target (once issues/settings.md is built)
- The first node of the reader's account to follow a version of a forked account writes it as an account setting (`settings` thing, key per forked account), and every node of the account places that version's line first, as a user's choice. A user's switch writes the setting.
- Two devices writing the setting at once: the setting's merge picks one, which one device then follows instead of its own first-seen line: one switch, made by the user's own devices agreeing, never back and forth by itself. State that limit in spec/permissions.md §5.4.

## Sync side
Nothing new: readers learn rotations as chain certificates under the labels the account's nodes open (spec/permissions.md §5.5, Chains travel), the rejection that raises the warning among them. A host delaying the revocation makes a reader follow the removed device's fork (stated in §5.5, Limit). The sync rewrite must keep delivering an account's rotations with their chains to every reader of a label the account writes under; issues/outsider-reads-nothing-after-node-removal.md is the gap seen today.
