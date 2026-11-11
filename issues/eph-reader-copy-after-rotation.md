# A reader's ephemeral copy cannot reach a host after a write-key rotation
> Summary: An ephemeral body held only by non-writers is lost to every other node once its host restarted and the label's write key rotated: a reader may relay only under its copy's old stamp, which the host refuses (code 9), and deposits take neither others' commits nor ephemeral blobs. Breaks spec/requirements.md Ephemeral data ("a node that restarts gets it back from those that still do"). Needs a design decision.
> Priority: normal
> Tags: ephemeral, sync, host, node

Reproducer: `cargo test -p osis-node --test it -- --ignored --exact ephemeral::repro_reader_copy_after_rotation_spec_sync_5`. a writes an ephemeral value; b (a writer) receives it and goes offline; the host and a restart (both lose it); a demotes b, rotating the write key; b comes back as a reader holding the only copy. b's relays get code 9 forever; a reads None, b the value.

Found as `ephemeral::ephemeral_reverts_with_restarts_alike_large_spec_crdt_4_6` seed 142475985505 (a's compaction snapshot held only by b after a host restart, an a restart and b's demotion while b was disconnected).

Why: spec/sync.md §5 Stamp: a host checks a stamp against its head's write key only; readers relay stamped entries (§6), so a copy stamped under a superseded write key is unrelayable. A durable entry is unaffected in practice: the host kept it across the rotation and writers persist their copies. An ephemeral entry goes with every host and writer restart, so readers' copies are often the only ones.

Options:
- **Readers deposit** a held must-hold body a host lacks when they hold no stamp valid under the head; a writer promotes it, co-readers read it at once (notes/inbox.md). Needs ephemeral deposits (held in memory at the host, refused today: spec/sync.md §5 Deposit, code 1) and deposits of others' commits (`may_deposit` takes only own role commits), under the deposit budget. Durable gains the same path (a new host after a rotation, where every writer lost a body).
- **Old stamps for ephemeral relays**: rejected. A removed writer keeps the old write key and could fill the host's ephemeral room.
- **State it as a limit**: weakens the requirement, so Tess's call.
