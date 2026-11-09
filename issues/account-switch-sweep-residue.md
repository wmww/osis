# Sim sweep failures left after the account switch
> Summary: After accounts author all commits, `sim-sweep` still fails `chat_join_leave` with a live index that differs from the rebuilt one on `secrets` (a held epoch's `supersedes` missing live), and `member_churn` once with a message storm. Neither showed in 100 seeds of main; causes not found.
> Priority: normal
> Tags: tests, engine, node-sync

Full sweep of `signing-6d` (seeds 0..100, 51 scenarios): 6 failures in 5100 runs. Two are older: `chat_join_leave` label not open at quiescence (seeds 32, 82; main fails it too), `copies_waiting` (seed 67, issues/deferred-copy-stuck-chat-leave.md).

- **Index differs from rebuild** (`chat_join_leave` 52, 65, `Engine` index check): in `Table("secrets")` a read epoch with `secret: None` has `supersedes: {}` live and its two predecessors when rebuilt, `rotations` equal. Property: the index is a function of the commits held. `supersedes` is filled from `keys.0` keysets (`apply::keys::keysets_of`, `RoleEpochs` in core/keys/src/epoch.rs); look for a `keys.0` part noted when its keyset reached the node some way other than a normal apply, or a keyset read only once the account's seed is held. `Engine::hold_account` re-reads `secrets.0` only.
- **Message storm** (`member_churn` 38, step 119): 5000 deliveries without the queue emptying, entries of content commits added over and over at the host. Reproduce with `osis_sim::replay`, then bisect by peer.

Spec and code differ on how an account reads a label: spec/sync.md §5 lists it by claim key (X25519 of its newest open epoch), the code by a static entry (`flows::account::reader_key`, `Try::Static`). Settle one with step (e).
