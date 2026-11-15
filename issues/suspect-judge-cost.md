# A suspect entry costs a digest of the whole aspect
> Summary: a writer judging a suspect entry digests its whole state of the aspect (`Engine::state_digest`: the state loaded with every page and encoded), again for every entry of every list, even when that state has not moved since the last judgement; so a proven reader of S can make a writer spend work in proportion to its state per ~50-byte entry, bounded only by flow control. Repairs themselves are bounded (once per state per reporter account). The fix is an engine one: a per-aspect state stamp and a memoized digest.
> Priority: normal
> Tags: engine, sync, security

- Where: `Engine::repair_suspect` (`tx.state(..).is_none()`, `state_digest` before and after a snapshot) per entry, called by osis-sync `inbox/suspect.rs` `judge`; the sender also digests every listed aspect per list sent per member.
- Bounded now: an aspect named twice in one message is judged once; entries of things outside S's readable closure, or aspects this node may not snapshot, stop at `may_repair` before any state is read.
- Fix: `state_digest` as a `Memo<(Tid, Ak), Option<[u8; 16]>>` over a `Stamps` keyed by aspect, written wherever a committed state of the aspect changes (`write_state` and the other direct `core.states` writers: apply/atomic.rs, groups.rs, refs.rs) and read by `state_digest`; the memo's debug comparison catches a missed writer. Then a repeated entry costs a row read and a memo hit, and a flood costs O(entries), not O(state).
- No magic number fits instead: capping entries per message or lists per pass bounds the rate, not the per-entry amplification.
- Also: a reporter's `I/s/` row of a thing since forgotten here stays until an entry of it shows the row stale (bounded by S's reader accounts times the aspects this node ever repaired); keying rows thing-first would let the thing's forgetting drop them.
