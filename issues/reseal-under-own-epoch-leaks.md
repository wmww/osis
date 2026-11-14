# Content another wrote, encrypted again under the sealer's epoch
> Summary: Engine side built (spec/crypto.md §5 Passing on, `labeling::opened`, Reseal.tla): a node encrypts another's part under an epoch it chooses (a section, a wrap, a copy, a snapshot carrying it) only while an epoch it opened a genuine section of that part under is established there; else the held section goes verbatim or nothing is made. Left: the new sync's calls (Sync side), header-only blobs' wraps, the openings' storage limits.
> Priority: critical
> Tags: security, keys, sync

The leak (reproduced: `rotation::tests_reseal`): a2 removes reader M (W); R, holding W, rotates read (e_R, boxing V and not M) and writes under it. V holds e_R's secret but not W (a host withholds it, or V holds A's demotion of a2 that voids W: the withdrawn-epoch shape), so e_R is not established at V and V's newest epoch is one M holds. A fresh encryption of R's write by V (node-sync `place` with no encryption held, a placement again past a delete), or V's compaction snapshot of the aspect, put R's content under V's epoch: M read it. Breaks spec/requirements.md Permissions ("removing a holder never re-encrypts existing content"; "stops reading new content once a writer has written after the removal").

## The rule (built)
- Content twin of R9: what a node read only under epochs not established at it, it passes on only as the ciphertext it came in. `Engine::open_commit` records per part the epoch each section opened under and the delta's hash (genuine: checked against the header where the thing's record is held, else compared with the held delta at use); `labeling::opened::passes_on` judges establishment at use (a demotion voiding W unestablishes e_R later).
- `Engine::seal`: every section of `extra` goes verbatim first; other parts are sealed under the node's epoch only where `passes_on`; else left out, and `None` when the body needs them.
- Wraps (`Engine::wrap_secret` with the body's parts): `None` while a part the blob carries does not pass on, so neither the header of a fresh encryption nor a per-label copy (whose wrap is its only gate) reaches a party the node does not know was removed.
- Snapshots (`retention::snapshot::may_snapshot`): a content aspect waits (`MayWrite::Later`) while a held body it would carry does not pass on.
- A part read in no section (an inbox payload, a direct connection, LocalPeer's plain delivery) passes on as before: it came under no epoch. So do role-class parts (records, keysets, roles, boxes sealed each to its recipient) and parts held with no content (dropped, value-less leftovers): only content parts are recorded, and a part's rows go when it is dropped or stripped.
- Model: core/test/tla/rotation/Reseal.tla (`run.sh reseal`): the build passes with liveness; sealing under the opened epoch itself passes too, established or not; the sealer's newest epoch, a forged opening counted, and establishment judged at the opening each leak.

## Sync side (for Capstan)
- Logging again, a deposit, any fresh encryption of a body: call `Engine::seal(body, class, sections, rng)` with `sections` = every section of every held genuine blob of the commit, opened or not (`OpenedBlob::sections`, not `sealed`), never a copy's. The engine copies them verbatim under a fresh blob key, salt and blob ID and seals only parts no given section carries. Old node-sync passes only unopened sections (`sealed_sections`), so a placement again of a body whose sections it opened under an unestablished epoch is refused there.
- `None` from `seal`: nothing may be made now (the body needs a part this node read only under an epoch not established here and no held section carries); retry when keys change (W arriving establishes e_R).
- Wraps: take the wrap secret from `Engine::wrap_secret(g, Some((commit, parts)))` with the parts the blob carries, every time (a reused blob too); `None` means the blob is not wrapped for that sync ID now.
- Every received commit blob goes through `Engine::open_commit` before its plaintext is ingested, in the same process: the openings ride in memory (`Core::openings`) until `put_commit` writes them beside the record.

## Open paths
- **Header-only blobs** (a lasting header, a body of no part this node holds): their wrap is judged on no part, so it goes under the node's newest epoch and hands the header to a removed party it does not know of. Closing it needs the epoch the commit's own entry was wrapped under: node-sync unwraps entries itself, so the new sync would tell the engine that epoch when it unwraps one (a proposed `Engine::note_unwrapped(commit, sync ID's thing, epoch)`), and the wrap of a header-only blob of another's commit would go under it, refused when it is not established here.

## Limits of the openings' storage
- A part first received in no section, later opened in one: its later openings are not recorded (a held part's re-open records nothing), so it stays passed on as read under no epoch. No content travels so in sync today.
- A store failure between opening and applying: the openings are kept in memory and written with the record; a restart in between loses them, and the commit's re-open after restart records them again (node-sync re-opens held bytes to ingest).
- Openings of blobs never ingested and of no held commit (a forged blob a peer served) stay in memory until restart.
- An aspect holding a write read only under a withdrawn epoch is never compacted at that epoch's box holders (the snapshot would carry it under their epoch).
