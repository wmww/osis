# A signal write can fire twice, or never
> Summary: firing is judged per apply or late join, with no memory of an earlier fire, so a write that leaves history and joins again (kick then re-grant, purge then the purge's fall) fires again, one that becomes history some other way (unstrip, validity flip of a kept body) never fires, and a later commit in the same transaction can drop a write that already fired.
> Priority: normal
> Tags: engine, signals

spec/commits.md §5 Signals says a node delivers a write once, when it becomes history here. `apply::atomic::fired` filters by `history::shows_value` right after each apply or late join; nothing records that a write fired.

Fires twice (reproduced, node test sketch below):
- Bob writes a signal, Alice applies it and fires. Alice kicks Bob with an empty frontier: the body is dropped as invalid. Alice re-grants Bob (spec/permissions.md §5.2 re-grant): the part is valid again, refetched from Bob, joins late and fires again.
- Same with a purge: fired, purged (stripped), the purge falls (`rejudge_purges` makes the part missing), refetched, joins late, fires again.

Never fires:
- A write that arrived purged (stripped) whose purge later falls without a refetch (an unstrip), or a kept invalid body (own commit) that turns valid: history shows it, no join happens.

Fires but never shown:
- `fired` runs at queue time, not at the transaction's end. A later commit in the same transaction (a cascade of waiting commits) can purge it or judge it invalid (`drop_invalid` runs at the end).

Likely shape: one rule, judged at the transaction's end: a part that `shows_value` and has not fired before fires and is marked fired (a persisted per-part bit in `Meta`). That covers every way into history and fires each write at most once.

Repro (core/node/tests/it/signals.rs helpers):
```rust
let (mut lp, d, ids) = setup(9);
let rx = lp.peers[0].engine.subscribe();
let c = send(&mut lp, 1, d, keep(Some(osis_commit::FOREVER), None), "hi");
lp.sync_all().unwrap();
assert_eq!(fired(&rx), vec![(c, s("hi"))]);
set_edge(&mut lp.peers[0].engine, d, ids[1], None, Some(ct::Frontier::default().to_value()));
set_edge(&mut lp.peers[0].engine, d, ids[1], Some(edge(Role::Write)), None);
lp.sync_all().unwrap();
lp.sync_all().unwrap();
assert_eq!(fired(&rx), vec![]); // fails: fires (c, "hi") again
```
