# A writer may remove admin boxes and history boxes from `/secrets`
> Summary: the role a `/secrets` delta needs is read from the entries it puts; an entry reset carries no key in the delta, so a delta that only removes entries (admin boxes, admin history boxes, a reader's current box) needs only write.
> Tags: security, engine

Severity: medium (nuisance and stranding; re-seal heals boxes, not removed history boxes until the next grant or re-seal of that epoch).

Scenario: writer W of actor A writes a membership commit whose `/secrets` delta resets the entries of every `(member, admin, e)` box and `(admin, e)` history box (keys known from W's state). `rotation_required` (core/engine/src/apply/validity.rs:506-545) computes the role from `f.read()`, which reads no removed entry: roles empty, so write. Valid; admins who had not opened the admin secret yet (new devices, restores) lose it until an admin re-seals; new members lose older epochs.

Spec: spec/crypto.md §4 "A rotation of role r ... removes the boxes keyed with role r at the epochs it supersedes ... boxes keyed with other roles are untouched"; spec/permissions.md §3 a writer rotates read and write only.

Fix direction: resolve each reset entry's key (`box_keys`, as `secrets_write` does; pend while unknown) and require the highest role among removed keys; optionally refuse a writer's removal of a box at a current epoch it does not supersede in the same commit.
