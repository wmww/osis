# Every label passes each resync, and a pass still grows slowly with labels
> Summary: after the labels-cost work a change, a connect and one write cost by what changed, but an idle node still runs one pass per label and connection per `resync_ms`, about 0.5 ms each at 500 labels (2.4 ms at 1000): most of a CPU core at 10^4 labels, idle.
> Tags: node, performance

`timers` marks every subscribed label dirty each `resync_ms` (heartbeats, timed bounds, entries refused for the cap). Measured with `scale::many_labels` (`OSIS_SCALE_SPANS=1`).

Two parts:
- How many passes: a label with an empty work set and nothing due could skip. It needs what is per pass anyway (`certificates`, heartbeat, promotion, reseal) to name its own next time, as `Work::due` does for bodies; then a tick costs what is due. Not tried: the harness in `work_sets.rs` should tell whether a trigger is missed.
- Cost per pass: at 500 labels `pass: certificates` is 0.32 of 0.5 ms; `tl.certificates` plus `cert_parts` for the label's chain 120 us and for each acting actor 75 us. The timeline reached from a label grows with what its owner holds.

Also O(labels) per event with a small constant: `add_new_labels`, `next_wake`, `labels()` per engine generation (about 75 us each at 500). They add to a connect's about 5 ms per label at 500, not to its round trips.
