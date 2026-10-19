# Rotation model: assumptions
> Summary: What Rotation.tla abstracts away from spec/crypto.md §4–§5, spec/sync.md §2/§5 and spec/permissions.md §3–§4, and why.

- **One actor, one role rotated: read.** Its label sits at one blind server. Write and admin secrets are never rotated, so step signatures (parent's delete key) and stamps always verify; the deposit key is always available. Rotating read is what decides who opens the label (sync key, claim keys, wraps).
- **Crypto is access.** `sec[x]` = epochs whose read secret x holds. A box is `x ∈ ep[e].boxes`; history box = `ep[e].hist`, all secrets the rotator held. Sealed vs symmetric box forms, KEM keysets and keyset epochs (departures *inside* a member) are not modeled: every member is a single node with one static key.
- **Epoch ids are nonces**: epoch `k` is the k-th rotation; ties in `n` break by lowest id. Forks arise from concurrent rotations.
- **Members** = `Admins ∪ Readers`, all granted at epoch 0; no grants later. Only `Remover` removes, only members of `Departing`. Demotion and `until` are not modeled (they are departures handled identically).
- **Rotation commit** is created locally and uploaded by its author after any needed re-registration; it is readable under `WrapOf(k)` = newest superseded epoch (crypto §5). A removal commit is wrapped under the remover's newest epoch.
- **Registration**: a step registers one read epoch; its claim set is the epoch's box holders as the global `ep` shows (the registrar is assumed to know all re-seals). Steps never fork (one server). Steps without a rotation (the MAY in sync §2) are not modeled.
- **Open** is one atomic check (`CanOpen`): a sync key held for some step on the path, then for every later step either its sync key or a listed, not-dropped claim key. The n round trips and step verification are folded into that check.
- **Inbox delivery** is reliable and needs no label access (the inbox label is assumed readable). A re-seal gives exactly the boxed epochs' secrets, not the history box (which stays in the rotation commit).
- **Stranded heartbeat** is placed (by deposit) when the node opens the label, cannot open the head's epoch and can download nothing more; admins see it at once.
- **Content** is one record per write: the epoch written under and the departures the writer knew. Writes happen only while the writer's newest epoch covers every departure it knows (otherwise `RotateForced` is enabled).
- **Delivery order**: `InOrder = TRUE` keeps the server log order between removals and later rotations (cursor sync); `FALSE` allows any order (range reconciliation, a second server or peer, a reordering server).
- **Claim-set drop** after `MEMBERSHIP_KEEP` is an unfair server step on any superseded step (time abstracted).
- **Liveness under weak fairness** of forced rotation, registration, upload, download, removal delivery, re-seal (a SHOULD, treated as done), heartbeat and inbox receipt. Eager rotation, removal, writes, claim-set drops and going offline are unfair.
