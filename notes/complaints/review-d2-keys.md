# Complaints: review-d2-keys
> Summary: Snags met reviewing d2-keys (roles-model may-grant as a flag).

- A "redundant" clause can be load-bearing elsewhere: G2's `role < Admin` in `flag_grant` also decides `need` for held writes not applied; removing it failed an osis-perm differential (`an_ended_value_restores_its_role`) that no roles-model test reached. Run `-p osis-perm` after any `paths.rs` rule edit.
- The Edit tool warns "file modified on disk since last read" after one's own python/sed edits: harmless, but it reads like another agent touched the file.
