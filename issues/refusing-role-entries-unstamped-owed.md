# a_peer_refusing_role_entries_plain: the owed-record effect reads something unstamped
> Summary: `sims::a_peer_refusing_role_entries_plain` (osis-sync) fails on main at seed 675321254093: the debug check on effects finds an owed `Record` kept for a sync ID where a settle reading nothing new gives none, so the effect read something unstamped.
> Priority: normal
> Tags: tests, sync, engine

- Replay: `OSIS_SYNC_START=675321254093 OSIS_SYNC_SEEDS=1 cargo test -p osis-sync --test it -- --ignored --exact sims::a_peer_refusing_role_entries_plain` (fails on 9f9a94418; `OSIS_SYNC_SHRINK=1` shrinks it). Found by the slim-a gate.
- `effects read: owed: Record(..) kept Some((Some(ConnId(..)), {SyncId(..)})), a settle with nothing it read written gives (Some(ConnId(..)), {}): it read something unstamped` (core/base/src/memo/effects.rs). Which input of the owed-record effect is read without a stamp is not found yet (issues/derived-state-recomputed.md lists the known unstamped reads).
