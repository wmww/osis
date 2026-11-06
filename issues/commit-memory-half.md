# A durable write's memory half is a second commit
> Summary: Four calls make one durable commit plus one memory commit under the same `ts` (a `delete` of a thing with ephemeral state, a draft's memberships leaving `placed.0~` when it is kept, a durable removal of a member also listed in `placed.0~`, a revert of such a write); the wire has no commit carrying both, so a peer can hold one without the other. What one commit would take, and the alternatives.
> Tags: engine, sync, spec, tess-call

Tess: a commit is an atomic write and is never quietly split. Today these `Write::commit` (and `revert`) cases make two commits, the durable one and a memory commit after it under its `ts` (engine `Engine::write`: `m.free`'s ephemeral resets and `Placed::eph` beside a durable half; `revert_change` for a logged batch with a commit):
1. `delete(t)` of a thing with ephemeral aspects or `placed.0~` memberships: the durable resets, then the ephemeral ones.
2. A draft's first durable write (or any durable write of a durable thing still in a `placed.0~`): the durable `group.0` adds, then the `placed.0~` resets.
3. A durable `w.group(g).remove` of a member also listed in `g`'s `placed.0~`: the durable removal, then the `placed.0~` one.
4. `revert`/`undo`/`redo` of a write that made two commits: the durable undo commit, then the memory one.

Nothing else splits: a user's own ephemeral writes beside durable ones, or plain beside expiring ones, are refused (`Clash`); a draft made with no write beside a durable write commits nothing for it (its record is held here). The sharing calls (`grant`, `sync`, `make_link` on a draft; `set_role` over a lost grant) make several commits on purpose and say so.

## Why the wire cannot carry it now
- spec/commits.md §2: a commit is one kind; an AK with `~` in a durable commit, or without `~` in an ephemeral one, is a bad part dropped alone; "a commit spanning several kinds is invalid".
- The marker is in the header (spec/wire.md §4) and the class in the blob prefix (spec/sync.md §1, §3): one commit is one blob per label, stored by hosts and nodes either in their logs and stores or in memory only (spec/sync.md §4, §9). Forms differ too: durable is commit form with retention, pages and `created.0`; ephemeral is session form, retention `writer`, no pages, records beside each part.
- So a peer can hold the durable commit without the memory one: after a restart, a host that lost its memory entries, a cap refusal (spec/sync.md §9 Caps), or a holder that forgot the memory commit. The case is benign today (the durable half reads right alone: a deleted thing's ephemeral values or a stale `placed.0~` entry show until the memory half arrives or the holders restart), but it is two commits.

## What one commit would take
A commit with parts of two storage classes, applied whole:
- Header: per part (or per delta entry) a storage class instead of one marker; the commit ID and signature cover both.
- Blob and prefix: either one blob whose durable entry holds the memory parts too (hosts keep it in their logs, so the memory half outlives restarts, against "never stored"), or two blobs under one commit ID (a durable one and a memory one, each with its class), applied by a receiver only once both are held (a durable commit then waits on a memory blob a restarted host lost: it must not; so the durable blob alone must apply, which is today's split again).
- Holding: a durable commit whose memory parts are forgotten at restart while the header stays, and verification of a part missing at one node and held at another (today `Meta::missing` for durable bodies).
- Forms: session-form memory parts inside a commit-form durable commit (two `dot` sources in one header).
None of this is small: every option either stores the memory half (no longer ephemeral) or lets the durable half apply alone (still two units on the wire).

## Alternatives without the wire change
- **Derive the memory half at every receiver.** A `placed.0~` entry of a thing that a durable `group.0` names in the same group reads as nothing (cases 2, 3: no reset needed; the stale entry goes at restart or by compaction). Changes spec/data-model.md §8 and the "a memory aspect's state is the join of its held parts" invariant only at read; needs a rule for a durable thing kept in `placed.0~` of a group the persisting node may not write (`MembershipNotSaved`).
- **Refuse instead of splitting.** `delete` of a thing with ephemeral state is `Invalid`, saying to delete its ephemeral side in a write of its own first (as `required.0^` mismatches already are, issues/delete-required-rules.md); the conversion in case 2 likewise. Explicit, but every app deleting a thing with a cursor writes two commits by hand, and an app that does not know about `placed.0~` cannot.
- **Keep two commits, documented** (today): notes/api.md Writes, spec/sync.md §9 and spec/commits.md §6 say these calls make two commits.

Tess: which? Until then, the docs say two commits.
