# A store removed and granted again while cut off from the admin holds nothing
> Summary: node 1 keeps t's S unread, node 2 reads it, node 0 removes node 1 and grants it Syncs again while cut off from it: node 1 then holds S (`sync_holder` Unread) but its store keeps none of S's entries, though node 2 holds them all. Connected to node 0 it refills. Found by the mutation audit: the only scenario reaching the opens rule "a peer no longer departed ends at `until` as any ended one" (`Opens::rejudge`, `m.departed && adm.j != J::Departed`), which no default test reaches.
> Priority: normal
> Tags: sync, tests

## Repro
In `core/sync/tests/it/keep.rs`, 3 nodes, 7.5 s (too slow for a default test as is):

```rust
let mut w = world(0, 3);
w.cap = 20_000;
let _ = play(&mut w, &[New(0), Grant(0, 0, 1, Gives::Syncs), Grant(0, 0, 2, Gives::Reads), Run], String::new());
let t = w.history.things[0].0;
let s = w.engine(0).sync_id_of(&t).unwrap().unwrap();
w.partition(0, 1);
let _ = play(&mut w, &[Revoke(0, 0, Holder::Node(1)), Grant(0, 0, 1, Gives::Syncs), Run, Write(0, 0), Run], String::new());
// node 1: sync_holder(&s) is Unread, store(1).entries(&s) is empty; store(2) holds 15
```

Without the partition node 1 holds 17 entries. The harness's quiet checks pass either way, so nothing at quiet says a store holding S lacks what a reader there holds.

## Open
- Why node 2's member toward node 1 does not reopen after the regrant (the departed member ends at its `until`, then closes; does node 1 open S again?).
- Whether a quiet check should compare a store holder's entries with its readers' (it would have caught this).
- Once fixed, a cheaper form of the repro guards the rule above.
