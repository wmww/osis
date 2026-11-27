# Slim C: an anchor promoted unchecked across connections, entries counted with no anchor, unbounded report state
> Summary: The Applied-counting design (a448ef112) has holes: an `anchor_new` from an earlier connection is promoted without being named, so a store restored in between can stay counted holding what it lost. Entries reported but not held as sent are counted with no anchor. A hostile peer can grow `Serve::told` (server) or `reporting` (requester) without bound. Plus "stream showed" wording left across the spec.
> Priority: normal
> Tags: sync, security, tests

## Anchor promoted unchecked (PresenceSound)
`Place::anchor_new` is durable, but `Pulling::checked` is per connection (core/sync/src/streams/pull.rs, `anchored`, `anchor_checked`). The sequence:
1. On connection 1, B sends an Applied with a1 before A's first reply checks a0, so a1 waits.
2. The connection drops.
3. B is restored to between a0 and a1.
4. On connection 2, A's Pull names a0 (valid), and the reply promotes a1 though nothing named it. A counts B holding what a1's Applied reported, until a later connection names a1.

Naming a1 alone on the new connection is no fix either: where a1 came from a restored history it does not vouch for a0's counts (as in `a_newer_anchor_waits_for_the_held_one_to_be_checked_spec_sync_streams_4`, with a drop before A's Pull). Both have to be checked. Either a Pull names both, or a1 promoted from an earlier connection stays unchecked and a Pull naming it is owed. Model it in NetStream first: a cfg with two take rounds and a drop between them.

## Counted with no anchor
`run` sends the anchor only where the Applied holds an entry as sent (`m: Some`), but the server counts every reported entry not told 14 (`serve.rs`, `reported_by`). That includes entries held under another stamp, held from another source after a gap, or fetched later. Those counts stand on no position of B's log, so the SN_echoanchor hole stays open for them. spec/sync-streams.md §4 Anchor and spec/wire.md §11.2 ("where it holds one of them as sent") state the same gap. Fix: carry the anchor whenever the Applied leaves any reported entry untold.

## Unbounded state from a hostile peer
- Server: `on_stream` inserts every `Refused(b, _)` under a member into `serve.told` before checking that the entry was sent. Bound it to entries an `asked` message's `Added` lists (`REPORTS_KEPT` bounds those).
- Requester: the gap branch extends `reporting` with every `Added` of every Stream passed over, cleared only when an Applied goes. A server that never answers the re-Pull grows it. One option: a Pull ends what earlier messages owe reporting (the server drops from `asked` every message after the cursor the Pull names).

## Sides disagree on what an Applied reports (suspicion)
An Applied naming a cursor the server dropped from `asked` (past `REPORTS_KEPT`) counts nothing and drops `told`, but the requester still adds those entries to `counted` and skips serving them back. The same happens with `taken` dropping messages in hand with their deferred `Batch::after` Applieds. So "reports" in spec/sync-streams.md §4 depends on a server-local bound.

## Smaller
- An untold entry goes as code 14 even where the requester refused it with a real code told before an earlier Applied. The spec says "its refusal's code where it refused it": reword it or keep the code.
- A store error reading the log end sends the Applied without an anchor while the server still counts. Fail the step instead.
- `ReplyInfo::named` (ded8ee884) has no test: an anchor held at once before the first reply, that reply a listing from the start.
- "Stream showed" wording, where presence is now `known` (Applied counts included): spec/wire.md §11.2 inline rule, spec/sync-ids.md Peer budget, spec/permissions.md (line about "its stream shows it"), spec/sync.md, spec/sync-judgement.md §3 ("never from what this node sent"), notes/sync-streams.md, notes/sync-store.md.
