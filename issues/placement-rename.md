# Retire "placement": a thing can be in many groups
> Summary: "placement" means making a thing an item or subgroup of a group, but the word implies a thing has one place, and it can be in many groups (owner). Say a thing is a member of a group, added to or removed from it. Rename across spec, notes, API (`place`, `place_expiring`, `unplace`, `place_plan`), `placed.0~`, and tests. The separate sync word "placed" (a commit held at a host, spec/sync.md §5) goes too.
> Tags: spec, api, naming

Owner direction, but talk to the owner before executing (after the chat design discussion). Textual plus names, in one branch with or right after issues/account-rename.md and issues/grant-rename-multi-actor.md, so hold until the other coordinator's engine and permissions wave is merged. Spec prose already defines "member" as this relation (spec/permissions.md §1), so most prose can say member directly; note a chat's "member" (an account with a role) is a different thing and app docs must keep them apart.

Names to pick in that branch: `add_to_group`/`remove_from_group` or similar; `placed.0~` (e.g. `members.0~`); for the sync sense, "uploaded" or "at a host". Scale: about 120 spec lines, about 480 notes lines and over 150 code files.
