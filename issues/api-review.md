# General API review
> Summary: The owner's whole-API review, to do with the owner: names and shape of the public `osis` API, CLI and the spec words behind them. Collects renames so they land together, after the other coordinator's engine and permissions wave, and talked through with the owner before executing.
> Tags: api, spec, naming

Renames:
- issues/account-rename.md, issues/grant-rename-multi-actor.md.
- "Placement" (owner): it means making a thing an item or subgroup of a group, but implies a thing has one place, and it can be in many groups. Say a thing is a member of a group, added to or removed from it. Touches `place`, `place_expiring`, `unplace`, `place_plan`, `placed.0~`, tests, about 120 spec lines, about 480 notes lines, over 150 code files. Sync's separate word "placed" (a commit held at a host, spec/sync.md §5) goes too; "uploaded" or "at a host". Spec prose already defines "member" as this relation (spec/permissions.md §1). A chat's member (an account with a role) is a different thing, so app docs keep them apart.

Shape, left for this review: issues/api-knows-empty.md, issues/api-leaving-give-up.md, issues/api-deferred.md. Undo's redesign was deferred to it too (notes/mvp-progress.md).
