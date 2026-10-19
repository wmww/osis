# osis-keys: replace `usable` by established epochs; what node-sync and membership-flows must implement
> Summary: The second TLC round made spec/crypto.md §4 "established" the one notion behind current epochs, history boxes, re-seal and registration (chain of applied rotation commits, `/secrets` snapshot base, persisted). osis-keys' `EpochInfo.usable` is a caller-set flag inferred from state on restart, which re-establishes an epoch got by re-seal (R9). Lists the keys changes and the obligations of the two wave-4 plans.
> Tags: keys, crypto, permissions, sync

## osis-keys
- `EpochInfo.usable` → `established: Option<Provenance>` with `Own | Fixed | Derived | Chain | Snapshot`, persisted through `SecretStore` and never inferred from the applied `/secrets` state (`observe_secrets`/`observe_keys` must not mark anything established; a re-seal's box or history box names an epoch without establishing it).
- A fixpoint helper: given the applied rotation commits (epoch → superseded set, from `SecretsWrite::rotations`) and the epochs a held `/secrets` compaction snapshot keys, compute establishment: `Chain` when the commit is applied and valid and every superseded epoch is established; `Snapshot` when keyed by a snapshot; derived epochs follow the owner's.
- `current()`/`is_current`/`newest*`: over established epochs; an unestablished epoch supersedes nothing and is never current (already so for `usable = false`).
- `rotate`: supersedes the current (established) epochs; `n` stays one above every known epoch; history boxes and carried roles (`may_carry`) take established secrets only.
- `box_member` (grant and re-seal): current established epochs; history boxes copied for those only.
- `reseal_needed`: takes the provenance and reports members missing a box only at `Chain`/`Own` current epochs; the caller passes only roles it may rotate and calls it at the end of a complete pass. Add a helper that says whether the newest current epoch is snapshot-established (the caller then rotates instead of re-sealing, if it chooses).
- `wrap_epoch`: newest current established; the stranded-heartbeat wrap: newest established secret held.
- `may_encrypt_under`: established and current and covering. Opening a label (sync-key derivation for an open) is allowed from any held secret: add `open_secret` or document that `label_role_key` for an open may take an unestablished secret, while stamps, steps and deletes may not.
- `registration_epochs`/`newer_than_head`: established epochs only.
- A `/secrets` compaction gate: `can_compact_secrets(epochs) == every epoch keyed by the state is established`.
- Tests: the R9 trace (re-sealed at e before e's commit; rotate; the removed member opens nothing of e), the reorder trace (e2 applied before e1 → unestablished; established once e1 arrives), snapshot base, the compaction gate.

## node-core
- Mark `Chain` establishment when a rotation commit is applied valid and its chain is established; re-run the fixpoint when a membership commit or a `/secrets` snapshot (with its pages) is applied; persist it. Keep headers of applied commits (spec/commits.md §5).
- Retention: before dropping a body with live writes (keep-at-most bound, at most 0, timed) a writer writes a covering snapshot when it holds none (spec/commits.md §5); the deletion queue entry for a timed delete carries "snapshot first".
- Carrier tiebreaks of spec/sync.md §7 (identical body: higher blob ID goes; covered-equal snapshots: higher commit ID goes).

## node-sync
- Per (label, server/peer) a "pass complete" event (log read to its end, `more = false`); `complete_pass(actor)` = complete at every server and peer it syncs the actor's labels with since the last membership commit of the actor applied from elsewhere.
- Re-registration order: download, then upload the actor's membership commits the server lacks under the head's keys, then register, then everything else (spec/sync.md §5).
- Stranded heartbeat: after a complete pass at that server when the head's epoch cannot be opened, or on a refused claim; wrapped under the newest established secret.
- Opens with the sync key of any held secret (an unestablished one included); stamps and deletes only with established epochs.

## membership-flows
- Re-seal: at the end of a complete pass, for members `reseal_needed` reports at chain-established current epochs, and for stranded heartbeats; at a snapshot-established newest epoch do not re-seal (optionally rotate).
- Rotation: boxes for members current in the timeline; history of established secrets only; a removal's rotation uploaded before the step (node-sync does the ordering).
- `/secrets` compaction only when `can_compact_secrets`.
