# What is left of per-label cost on an idle or quiet node
> Summary: an idle subscribed label costs no pass, but a node's tick still walks every label (about 3.5 µs per label and node a minute), each event has O(labels) bookkeeping, and one pass still grows slowly with labels (0.12 ms at 100, 0.4 ms at 1000).
> Priority: low
> Tags: node, performance

Idle: notes/node-sync-work-sets.md Idle labels; counted by osis-sim `scale::label_costs_do_not_grow_with_labels`, `idle_labels_pass_only_when_due` (notes/testing.md Scale checks); the per-label tick walk and bookkeeping are not counted.

- The tick: `timers` and `next_wake` walk every label, `next_wake` at every event. A due index (an ordered set of times) would make them follow what is due, at the price of more sites to keep it right; at 10^4 labels this is about 35 ms per node a minute, not noticed yet.
- `spread_touches` copies each commit into every label's work set, and `add_new_labels` and `labels()` walk them all: O(labels) per event. A set that waits long goes `full` past `work_max`, so a quiet label with busy neighbours judges everything at its next resync. Spreading a commit only to labels it concerns would end both, but the marks' exactness would then carry the verdicts too.
- A pass: `pass: certificates` is most of it. The rest of the growth was not found.
- Heartbeats stay per label: a pass and an upload per `HEARTBEAT_MIN_INTERVAL` for each label, which is what a node with 10^4 labels idles on.
