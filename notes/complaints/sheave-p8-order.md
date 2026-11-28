# sheave-p8-order
> Summary: the arrival-order property had no replayable script form; shrinking its failing order by "held differs" drifted to another difference.

- `arrival_order_holds_alike_*` built its random history inline, so a failing seed could only be replayed whole (about 100 s to build its world each time) and a hand test meant re-deriving the steps by guesswork (two hand-built histories missed the state). It now plays a `Step` list (`Arrival::play`), so the logged steps are a hand test directly.
- Shrinking the failing order by "N holds differently from in order" kept a different difference (N a reader in both, a lost read box) instead of the reported one (removed N keeping sync secrets): a shrink must keep the failure's own assertion, not mere inequality.
