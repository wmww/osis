# A rotation's thing list for T does not reach S's other readers
> Summary: an account rotation's thing list for a thing T under S stays at the rotator; the other nodes reading S never hold it, so the account's commits on T at the closed epoch are invalid everywhere else.
> Priority: normal
> Tags: sync

- Seen in the setup of `flows::old_rotation_lines_go_as_headers_alone_spec_permissions_4` (core/sync/tests/it/flows.rs): node 0 makes T, files it in its D and grants account a1 write; node 1 (a1) files T and writes on it, then rotates (`Engine::rotate_account`, test hook over `flows::signing::rotate_in`).
- At node 1, `rotation_lists(r)` names node 1's write under T; at node 0 and at a later reader of S, it lists no T for r, and `list_rotations(S)` there holds only the first rotation of three. The write is held invalid at both (`held_part(..).valid == false`): unlisted at a closed epoch (spec/permissions.md §5.5 Epoch rule).
- spec/sync-judgement.md §1 (List blobs) and spec/permissions.md §5.5 (the rotator logs, with r, the thing lists of the things under each sync ID it opens) say the list goes under S. Unknown which side drops it: the rotator not sealing a list blob under S, or the others not holding it (held only once its rotation is; rotations reach S's readers as header-only certificate copies).
