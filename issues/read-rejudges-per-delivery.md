# read judges a body again after each delivery
> Summary: Node::handle settles every module after each input, and read's `judged` re-runs a body's judgement each time one of its reads moved: 7-21 judgements per (node, S, commit) in a run to quiet, two thirds to three quarters of them giving the answer already held, and the re-runs per round grow with the rounds already played though deliveries and moved answers stay flat. Read's settle is about a third of osis-sync's default-test instructions (Node::settle about 60%).
> Priority: normal
> Tags: sync, performance, tests

## Measured
Counts from a scratch probe (osis-sync `read::Read::settle_on`, the `judged` loop): judgements (`read: judged`), answers that moved (`try_settle` returning `Some`), distinct (node, S, commit) keys judged, per phase of three default tests. Deliveries are `World::deliveries` in the phase.

| phase | deliveries | judgements | moved | keys |
|---|---|---|---|---|
| `duties::sibling_removals_apart_both_hold_through_sync_spec_permissions_3`, the heal run | 172 | 5,272 | 1,343 | 249 |
| `growth` grant arm, round 1 | 53 | 470 | 158 | 66 |
| `growth` grant arm, round 10 | 53 | 692-802 | 153-163 | 144-203 |
| `growth` lowered writes, restart and tombstone lifetime | 160 | 1,908 | 550 | 498 |

- Per key, a run to quiet judges a body 7 (grant round) to 21 (heal) times; its answer moves 2-5 times (each delivery bringing a part of the picture), and 66-75% of the runs return the answer already held.
- The grant arm plays the same round each time (53 deliveries, about 47 fresh keys, about 160 moved answers per round), yet its judgements per round rise from 470 to about 700-800 by the tenth: bodies of earlier rounds are judged again by each later round, while answering as before. Work per change grows with history (spec/requirements.md Scale), which `growth::` does not check: it counts storage, not work.
- cpuprof (instruction-sampled, one thread): `Node::settle` 57% of `growth::`, 61% of `holding::`, 70% of the duties test; `Read::settle` 32-37% of each; `Node::dispatch` (taking the messages themselves) 12-18%.

## Direction
Find what moves under an unchanged answer: which reads of `judge::body` move per delivery (issues/test-time.md, Levers 2 names the suspects: blobs at S, presence at a source, own entries, `may_log`'s role reads through `role_now`), and why bodies of earlier rounds are re-judged in later ones. Narrow those reads to what the answer depends on (fast by construction), rather than settling less often: a node settles after every input by design (sans-IO step), and batching inputs would hide the cost from tests without removing it from nodes. Then a scale test counting judgements per round at n and 10n rounds (the grant arm's shape) guards it.
