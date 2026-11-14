# Sync: hostile peers
> Summary: Area 8: what a hostile peer can and cannot do to sync, the bounds on its input, and the stated limits.

**Principle:** a peer's word changes only what that peer holds; nothing it says is taken as identity, authorization or deletion, and every message costs bounded work.

## 1. Bounds
- Identity and authorization come only from proofs on the connection (spec/sync-opens.md §2) and from verified data; a stream's `Deleted`, a refusal, a head the peer names, a payload sync ID and a hint are its word only.
- Bad bytes are ignored; no peer input causes unbounded allocation, work, storage or diagnostics (spec/wire.md §13).
- A filter breaking spec/wire.md §11.2 Beacons is answered Error 2 and closes the connection. One test pass in flight per peer.
- Records, Resume, Beacons, Pull and Members floods are bounded by message size, `max_reply`, `RECORD_BUDGET` and the shared set; only a known actor can make records.
- An ephemeral commit is room-checked whole before any decode and waits only once its signature checks.
- Unstamped entries a peer brings count against its peer budget (spec/sync-ids.md §5); deposits against the deposit budget (spec/sync-inbox.md §3).
- Nothing reads a clock above the transport: a skewed peer affects only its own writes.
- A peer without a credential or J learns only the entry count of its own filter and random bits; beacons are unlinkable across peers; only ByRole, Lost and Deposit items carry a sync ID, each to a judged holder.
- A node holding only S's public values opens nothing; a static item reflected through a second dial, or an older step's signature, opens nothing toward the peer.
- A removed sync holder gets nothing after the rotation's step; a removed reader or revoked link learns at most one rotation past what it read.
- A forged head or box, or a substituted box, teaches nothing; a forged grant is not offered again.
- A peer that drops what it pulls cannot keep a node from idle: lacking counts only what a source pulls.
- A peer lying in its own log (hiding a cover) costs at most one logging again per change of ground (spec/sync-judgement.md §4).

## 2. Stated limits
- A revoked node of a known actor holds only the closed epoch's key; a verifier not yet holding the rotation counts its proof (the account signing fork window).
- A node keeping S unread shows that it keeps S to anyone holding S's public values (its filter goes to every connection).
- A depositor holding a team's `keys.0` but not its roster learns from 0 against 14 whether a node holds the team's inbox (team membership of that node's account).
- A peer showing an actor's inbox deposit key (anyone holding that actor's `keys.0`) is offered the inbox blobs a connected node sends that actor (spec/sync-inbox.md §3): it learns that this connection's node sends to that inbox, when, and the blobs' padded sizes.
- A known peer can force work linear in its filter per small message (each additions page re-sorts and tests; a Hit then Lost re-tests); there is no rate limit.
- A peer can refuse role entries or hold requests open: what waits on it there (deletes, logging again) waits, the stall rule closes the connection (spec/sync-streams.md §1), and other sources are unaffected.
- A writer may stamp any entry as a role entry past the caps (spec/sync-ids.md §6 Role entries). Anyone able to deposit can fill the deposit budget while no admin is online (spec/requirements.md). A lowered holder can delete at a node keeping S unread what its old role allowed until a writer logs it again (spec/permissions.md §6).
- A dialer proves to any key it chose to dial (spec/sync-opens.md §2), so a key it was given by discovery or configuration learns its identity.
- A node keeping S unread can be made to keep ciphertext of a removed grant until the removal notice reaches it, or for good when no admin signed one or the remover's state lacked its newest box (bounded by its caps and by its account unlisting the thing; spec/sync-judgement.md §6 Stops).
- A body dropped as invalid is never deleted at a peer (spec/sync-judgement.md §3 Deletes), so a writer's invalid entry can take a full store's room there until it expires or the caps give way.
