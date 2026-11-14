# Sync: hostile peers
> Summary: Area 8: what a hostile peer can and cannot do to sync, the bounds on its input, and the stated limits.

**Principle:** a peer's word changes only what that peer holds; nothing it says is taken as identity, authorization or deletion, and every message costs bounded work.

## 1. Bounds
- Identity and authorization come only from proofs on the connection (spec/sync-opens.md §2) and from verified data; a stream's `Deleted`, a refusal, a head the peer names, a payload sync ID and a hint are its word only.
- Bad bytes are ignored; no peer input causes unbounded allocation, work, storage or diagnostics (spec/wire.md §13).
- A filter breaking spec/wire.md §11.2 Beacons is answered Error 2 and closes the connection. One test pass in flight per peer.
- Records, Resume, Beacons, Pull and Members floods are bounded by message size, `max_reply`, `RECORD_BUDGET` and the shared set; only a peer that proved an actor makes a record.
- An ephemeral commit is room-checked whole before any decode and waits only once its signature checks.
- Unstamped entries a peer brings count against its peer budget (spec/sync-ids.md §5); deposits against the deposit budget (spec/sync-inbox.md §3).
- Nothing reads a clock above the transport: a skewed peer affects only its own writes.
- A peer without a credential or J learns only the entry count of its own filter and random bits; beacons are unlinkable across peers; only ByRole, Lost, Behind and Deposit items carry a sync ID, each to a judged holder, except a Deposit reaching a peer through a false positive of its filter (spec/sync-inbox.md §3 Sending), which learns nothing beyond the deposit's existence.
- A node holding only S's public values opens nothing; a static item reflected through a second dial, or an older step's signature, opens nothing toward the peer.
- A removed sync holder gets nothing after the rotation's step; a removed reader or revoked link learns at most one rotation past what it read.
- A forged head or box, or a substituted box, teaches nothing; a forged grant is not offered again.
- A boxes payload's sync IDs and dial hint are its sender's word: a node keeping a thing unread keeps or dials one only once its account kept it (an accept or its own reading, spec/sync.md §3), and records a secret only once a step on its own path bears it.
- A node keeping S unread drops its copy only when a Register verified on its path moves its head (a head a peer names, a stream or a box moves nothing).
- A peer that drops what it pulls cannot keep a node from idle: lacking counts only what a source pulls.
- A peer lying in its own log (hiding a cover) costs at most one logging again per change of ground (spec/sync-judgement.md §4).

## 2. Stated limits
- A revoked node of an account holds only the closed epoch's key; a verifier not yet holding the rotation counts its proof (the account signing fork window).
- A node keeping S unread shows that it keeps S to anyone holding S's public values (its filter goes to every connection).
- A depositor holding a team's `keys.0` but not its roster learns from 0 against 14 whether a node holds the team's inbox (team membership of that node's account).
- A peer showing an actor's inbox deposit key (anyone holding that actor's `keys.0`) is offered the inbox blobs a connected node sends that actor (spec/sync-inbox.md §3): it learns that this connection's node sends to that inbox, when, and the blobs' padded sizes.
- A peer can force work linear in its filter per small message (each additions page re-sorts and tests; a Hit then Lost re-tests); there is no rate limit.
- A peer can refuse role entries or hold requests open: what waits on it there (deletes, logging again) waits, the stall rule closes the connection (spec/sync-streams.md §1), and other sources are unaffected.
- A writer may stamp any entry as a role entry past the caps (spec/sync-ids.md §6 Role entries). Anyone able to deposit can fill the deposit budget while no admin is online (spec/requirements.md). A lowered holder can delete at a node keeping S unread what its old role allowed until a writer logs it again (spec/permissions.md §6).
- Under the default policy a node proves its actors to every peer (spec/sync-opens.md §1 Policy), so any node it connects to, whoever dialed, learns its account. Any peer learns about how many credentials a node shows (its filter's entry count). A peer proving fresh actors makes a record at each connection, holding its filter (up to 2^22 entries and as many additions): a few such connections pass `RECORD_BUDGET`, the least recently used records go, and their peers are read from the start at their next connection.
- Departed (spec/sync-opens.md §4) is judged only of a proven actor: a departed party proving none opens S by a current read secret or sync proof it still holds, until the rotation covering its departure is held here.
- A node keeping S unread whose box of its head's sync secret arrives after that step's Register (a late box, or a grant again before its new box) drops its copy and fetches S again (spec/sync-judgement.md §6 Stops); what only it held is lost, what a reader holds is not.
- A removed admin holding the delete key of a step on a node's path, before that node registered the step past it, can register there a child under a sync key the node holds no box for: the node drops its copy, and its head is on a branch no reader records, so it holds S again only once its account unlists and lists the thing again (leaving shreds its path); the account records a sync secret it boxes for each step it registers there. Registering a closing step there (spec/wire.md §8) instead closes S at that account (spec/sync-judgement.md §6 Closes): it holds S again only once it accepts an offer of it again.
- A body dropped as invalid is never deleted at a peer (spec/sync-judgement.md §3 Deletes), so a writer's invalid entry can take a full store's room there until it expires or the caps give way.
- Anyone able to seal a box to a node's account key can box it a sync secret of a thing it keeps unread at a self-made sync epoch: the node shows that secret's sync key with no head or past its keys (spec/sync-opens.md §4), which no reader holds, while the blob is held; it hides no genuine key, is never recorded and keeps no copy past a removal.
- The sync record is an account's: of a group actor holding sync alone, each account reading it accepts the thing itself, and one reading it from past `INBOX_LIFETIME` after a box gets none until the thing's next rotation or a re-seal.
- The user may accept an offer whose sync ID is a forger's (the granting account shows only when its signature verifies under a key held, spec/sync-inbox.md §2): the thing is then kept under that sync ID too, with what its owner registers there, within the caps; the genuine sync ID is kept once an offer of it is accepted. An offer naming a sync ID the record keeps for another thing keeps nothing; one accepted before the genuine thing's (a holder of that thing offering a thing of its own under its sync ID) keeps the genuine thing from that sync ID at this account.
- A node past its keys holding the sync secret of an epoch no step bears shows it, and a reader holding that secret opens S there; nothing moves (the node takes nothing).
