# history-read-review
- `OSIS_ORDER_DUMP` prints nothing for an order "with late parts", the failing kind in seed 3050.
- A background command piping a test run through `grep` shows nothing if `timeout` kills the run; write to a log and grep after (lost a 7-minute cost probe to a fill far slower than guessed).
- A scratch clone's cold `-p osis-node` test build was fine on tmpfs, but its target is another few GB of RAM there.
