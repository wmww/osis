# Spec rules without code or test, and code rules without spec
> Summary: Per spec file, the rules a rule-by-rule read found unbuilt, contradicted or untested, and code enforcing what no spec states; each with a line of judgement. The small clear ones are fixed; this lists what is left.
> Priority: normal
> Tags: tests, sync, engine, crdt

Judgement in brackets. Line numbers drift; grep the quoted words.

## spec/commits.md
- §5 the setting: `history` keep "until T and/or for D after replaced, at least one". `History::Keep { until: None, after: None }` decodes, fits and is written. [Small: refuse it at the writer, or drop "at least one".]
- §2 ephemeral shape (no purge request, no list by link, content kind only): checks in `commit/src/validate.rs`, no test. [Small test.]
- Code only: the builder refuses an aspect list by link on a commit carrying its signer's `created.0` (`commit/src/builder.rs`, the list key needs the signer's record). [State in spec/wire.md §4 Inline or link, add a test.]
- Code only: a role commit's `Path` may name no purge author but the signer (`path_allowed`); tracked in issues/stated-path-certificates.md. [Large.]

## spec/data-model.md
- §1 record collision: "keep the held record ... report a diagnostic". `learn_record` (record blobs) keeps it silently; the commit path reports `CollidingRecord`. No test. [Low value: needs a 120-bit collision; consider deleting the diagnostic clause.]

## spec/crdt.md
- §8 Facts: "a purge author equal to the signer" is bad input (`wire.rs`, "fact purge author is the signer"); the model leaves it unmodeled, no test. [Small test.]
- §8 Absorbed: sorted by commit ID, each once (`codec.rs`, `stream.rs`); the model refuses every non-empty table, so the decoder differential never reaches these. No rejection test. [Small test; or model it.]

## spec/permissions.md
- §5.1 Sides, the counter-removal told beside its disputes: only roles-model builds it (`countered`); `Engine::disputes` lists none. [Medium: port the model's rule.]
- §5.1 Sides, "cannot stand beside" and choosing R dropping the others: unbuilt (`sides.rs` comment); "Its own" records lazily, equivalent only while that is unbuilt. [Medium/large, together; notes/perm-paths.md Read short of the spec.]
- §5.1 The list (leave out what moves `end(F)` earlier): unbuilt, the frontier lists everything; so the writer refuses a removed admin's counter-removal, a writer rule no spec states (the test needs `skip_writer_rules`). [Large.]
- §7 a link ended once every route refused L's claim key: unbuilt (issues/sync-link-first-contact.md). [Medium.]
- §7 K's `retain` default written at link making, and §2 "`until` 0 for nothing else": code, no test. [Small tests.]
- §5.2 "A part on a core aspect is invalid" (ephemeral parts): no check; a core-form ephemeral AK may not be reachable. [Unsure: delete the clause if unreachable.]

## spec/crypto.md, spec/sync-compaction.md
- compaction §2 Caps: an ephemeral entry refused for room is fetched again once held bytes drop. Unbuilt, and worse: `memory_gate`'s `TooLarge` reaches sync as a held entry (`streams/mod.rs` `Opening::Held`), logged and charged to nobody while the engine holds no commit. [Medium; a real bug.]
- compaction §2 relay-only delivery, `MAX_DELIVERED` floor, `MAX_DRIFT` drop: `Engine::ingest_relay_blob` has no test (sync tests mock it). [Small engine test.]
- compaction §2 Superseded parts: code adds two conditions no spec states (no superseder while the setting keeps history; none of a `Seq` or `Bag` fragment, `retention/memory.rs`). [Small: state them, or drop them if not needed.]
- crypto §1 "Batch and single verification MUST agree": no batch verification exists. [Keep for other implementations, or drop.]
- sync-hostile §1 "One test pass in flight per peer": "test pass" is defined nowhere. [Reword to opens' term.]

## spec/sync-ids.md, spec/sync-judgement.md, spec/sync-inbox.md
- sync-ids §6 Register "in its sync set": code takes Registers for a sync ID left and waiting to stop (`path.rs` checks only `Unread`). [Small; decide which, likely the spec: S is kept while it waits.]
- Code only: a Deposit item at a stopped store is answered 4 (`store/mod.rs`, path filtered by `unheld`); a stamped entry pulled there 1, an ephemeral one without bytes 2. [Small: state the codes, or answer 14.]

## spec/sync-opens.md, sync-set.md, sync-status.md, sync-streams.md, sync-transport.md
- Code only: an out-of-order Digest or Members closes the connection (`opens/mod.rs`). [Small: state it in sync-opens §3.]
- Code only: a dialer closes when its Prove is answered by anything but Proved (`session.rs`). [Unsure whether stated.]

## spec/wire.md
- §11.2 Stranded "answered Ok whatever the receiver does with it": a store failure answers Error 1 so the reporter sends again. [Low: a local failure, not a judgement; state it or leave.]
- Code only: `MAX_WRITE_OPS` (1024 ops in one client write), stated in notes/client-port.md alone. [Low while the client port's ops are a note.]
- §9 `HolderKeys` takes two positions inside Stranded; notation ambiguous. [Spell Stranded out.]
