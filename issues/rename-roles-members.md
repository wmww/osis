# Rename: rights are roles, group placement is membership
> Summary: owner decision: the rights edge (actor, target, role) is a **role grant** ("Dana has write on X"), the `/members` aspect becomes `/roles`; "member"/"membership" from now on means only group organization ("this note is a member of the Work group"), `/group`/`/groups` unchanged. Rename across spec, notes, code, API, tests; no compat (CLAUDE.md).
> Tags: spec, api, permissions

- Today "member"/"membership" means the rights edge throughout spec/permissions.md, spec/crypto.md, code (`member_keys`, `MemberOf`, `/members`, roster) and the `osis` API; spec/permissions.md §1 also calls `/group` "group membership". After: rights words are role / role grant / holder ("a holder of write on X"); organization words are member / membership / member of a group.
- A mechanical but wide pass: spec first (one terminology section in spec/permissions.md §1 and spec/data-model.md), then crates bottom up, then notes and issues. Wire tags and field names change in place (no stability yet); regenerate vectors.

Owner (round 13): do it in one sweep with issues/one-node-kind.md; the result must read as if built that way from the start (reviews hunt for remnants of the old words in code, API, CLI, errors, tests, spec, notes).
