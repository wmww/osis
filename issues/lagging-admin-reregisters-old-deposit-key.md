# A lagging admin re-registers the old deposit key
> Summary: after an admin refreshes the deposit seed alone (`refresh_deposit_seed`, no rotation) and registers a step, another admin that holds the same epochs but has not yet applied the `/keys` write sees the head's deposit key differ from its seed; `reregister` runs before the pass downloads, so it issues a step back to the old deposit key. The first admin then steps again. Bounded (one extra step each until the laggard applies the write) but the old key, and so a departed party's deposits, are accepted again meanwhile.
> Tags: sync, security

Severity: low. A read rotation's refresh is immune: the seed is in the rotation commit, and an admin without the head's epochs issues nothing.

Where: core/node/src/sync/pass.rs `step_due` (`refreshed`), `reregister`; core/engine/src/flows/labels.rs `issue_step`.

Fix direction: a deposit-only re-registration waits until after the pass's download (or the next pass), or `refresh_deposit_seed` is folded into a read rotation.
